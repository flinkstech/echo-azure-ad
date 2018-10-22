package authenticate

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/ipfans/echo-session"
	"github.com/labstack/echo"
	"github.com/mendsley/gojwk"
)

type (
	// AuthSettings is used as an argument to Init
	AuthSettings struct {
		ClientID     string
		TenantID     string
		ClientSecret string
		RedirectURI  func(echo.Context) string
		Skipper      func(echo.Context) bool
	}

	// ActiveDirectory is like AuthSettings but with methods and stores internal states
	activeDirectory struct {
		ClientID     string
		TenantID     string
		ClientSecret string
		RedirectURI  string
		Skipper      func(echo.Context) bool
		Keys         []gojwk.Key
	}

	stsPostData struct {
		IDToken      string `form:"id_token"`
		Code         string `form:"code"`
		State        string `form:"state"`
		SessionState string `form:"session_state"`
	}
	//https://docs.microsoft.com/en-gb/azure/active-directory/develop/v1-id-and-access-tokens
	//https://graph.windows.net/{tenantID}/users/{userID}/getMemberObjects
	activeDirectoryClaims struct {
		AMR        []string `json:"amr"`
		FamilyName string   `json:"family_name"`
		GivenName  string   `json:"given_name"`
		IPAddr     string   `json:"ipaddr"`
		Name       string   `json:"name"`
		Nonce      string   `json:"nonce"`
		OID        string   `json:"oid"`
		OnPremSID  string   `json:"onprem_sid"`
		TID        string   `json:"tid"`
		UniqueName string   `json:"unique_name"`
		UPN        string   `json:"upn"`
		UTI        string   `json:"uti"`
		Ver        string   `json:"ver"`
		jwt.StandardClaims
	}

	// User is a representation of the useful user data returned in an id token
	User struct {
		Username        string
		FirstName       string
		LastName        string
		Email           string
		Groups          []string
		Data            map[string]interface{}
		IsAuthenticated bool
		IsStale         bool
	}

	sessionStore struct {
		IDToken *activeDirectoryClaims
		Groups  []MemberGroup
	}

	//AuthContext extends echo.Context to contain a reference to user information
	AuthContext struct {
		echo.Context
	}

	authValues struct {
		User        *User
		clientID    string
		tenantID    string
		redirectURI string
		authority   string
		skipper     func(c echo.Context) bool
	}
)

const (
	gracePeriod     = 24 * time.Hour
	sessionStoreKey = "echo-azure-active-directory-session-key"
	urlTemplate     = ("https://login.microsoftonline.com/%s/oauth2/authorize?" +
		"client_id=%s&response_type=id_token+code&redirect_uri=%s" +
		"&response_mode=form_post&scope=openid&state=%s&nonce=%s")
)

var contextStoreKey = uuid.New().String()

// EchoADPreMiddleware is echo pre-middleware
func EchoADPreMiddleware(settings *AuthSettings) echo.MiddlewareFunc {
	a := &activeDirectory{}
	a.ClientID = settings.ClientID
	a.TenantID = settings.TenantID
	a.ClientSecret = settings.ClientSecret
	if settings.Skipper == nil {
		a.Skipper = func(c echo.Context) bool { return false }
	} else {
		a.Skipper = settings.Skipper
	}

	gob.Register(sessionStore{})
	gob.Register(activeDirectoryClaims{})
	gob.Register(MemberGroup{})

	authority := fmt.Sprintf(urlTemplate, settings.TenantID, settings.ClientID, "%s", "%s", "%s")

	// This is the pre-middleware that listens for a login redirect from the authority
	// we also supply some data to the context based on initialization to perform the redirect
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ec echo.Context) error {
			c := &AuthContext{ec}
			user := c.userFromSession()
			c.Set(contextStoreKey, &authValues{
				user,
				a.ClientID,
				a.TenantID,
				settings.RedirectURI(ec),
				authority,
				a.Skipper,
			})

			if c.Request().Method == http.MethodPost {
				var bodyBytes []byte
				if c.Request().Body != nil {
					bodyBytes, _ = ioutil.ReadAll(c.Request().Body)
				}
				c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

				var form stsPostData
				err := c.Bind(&form)

				c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

				if err != nil || !(form.IDToken != "" && form.Code != "" && form.State != "" && form.SessionState != "") {
					// If we can't bind, the POST was not from the authentication authority
					return next(ec)
				}

				// If the form is valid, tell Echo that we want the GET route
				ec.Request().Method = http.MethodGet

				// If these conditions are met, it's because an old GET-converted POST was refreshed
				if user.IsAuthenticated && !user.IsStale {
					return next(ec)
				}

				token, err := jwt.ParseWithClaims(
					form.IDToken,
					&activeDirectoryClaims{},
					func(token *jwt.Token) (interface{}, error) {
						a.RedirectURI = form.State
						return a.getKey(token.Header["kid"].(string))
					})
				if err != nil {
					msg := "id_token invalid or absent"
					return c.String(http.StatusInternalServerError, msg)
				}

				if claims, ok := token.Claims.(*activeDirectoryClaims); ok && token.Valid {
					// The token signature has been verified, but check that the nonce was
					// generated by us to fend against claim impersonation
					sess := session.Default(c)
					sentNonce, _ := uuid.Parse(sess.Get("auth_nonce").(string))
					receivedNonce, _ := uuid.Parse(claims.Nonce)
					if sentNonce == receivedNonce {
						groups, _ := a.getGroups(form.Code)
						// Add user to session for future requests
						sess.Set(sessionStoreKey, &sessionStore{
							IDToken: claims,
							Groups:  groups,
						})
						sess.Save()
						// Add user to context store for the current request
						c.Set(contextStoreKey, &authValues{
							userFromClaims(&sessionStore{
								IDToken: claims,
								Groups:  groups,
							}),
							a.ClientID,
							a.TenantID,
							settings.RedirectURI(ec),
							authority,
							a.Skipper,
						})
						return next(ec)
					}
				}
				return c.String(http.StatusUnauthorized, "Authentication failed")
			}
			return next(ec)
		}
	}
}

func (ac AuthContext) userFromSession() *User {
	// Retrieve data from session, if it exists
	sess := session.Default(ac)
	if sess == nil {
		return defaultAnonymousUser()
	}
	store := sess.Get(sessionStoreKey)
	if store == nil {
		return defaultAnonymousUser()
	}

	storeData, ok := store.(sessionStore)
	if !ok {
		return defaultAnonymousUser()
	}

	return userFromClaims(&storeData)
}

func userFromClaims(storeData *sessionStore) *User {
	// Determine validity
	expiresAt := storeData.IDToken.StandardClaims.ExpiresAt

	// If we are past the grace period, return default user and wipe session
	if expiresAt <= time.Now().Add(-gracePeriod).Unix() {
		return defaultAnonymousUser()
	}

	/* It is up to the handler to decide how to handle an authenticated, stale user.
	* The preferred behaviour is to accept a form submission but not continue the
	* session without checking with the authority. Echo does not expose an easy
	* way to do this automagically.
	 */
	stale := false
	if expiresAt < time.Now().Unix() {
		stale = true
	}

	groupNames := []string{}

	for _, group := range storeData.Groups {
		groupNames = append(groupNames, group.DisplayName)
	}

	return &User{
		LastName:        storeData.IDToken.FamilyName,
		FirstName:       storeData.IDToken.GivenName,
		Username:        storeData.IDToken.UniqueName,
		Email:           storeData.IDToken.UPN,
		Groups:          groupNames,
		IsAuthenticated: true,
		IsStale:         stale,
	}
}

// User returns the user attributed to the given context
// the context store is checked first for the case
// where the user was just assigned by the middleware
// and cannot yet be retrieved from the session
func (ac AuthContext) User() *User {
	store := ac.Get(contextStoreKey)
	if store != nil {
		values, ok := store.(*authValues)
		if ok && values.User.IsAuthenticated {
			return values.User
		}
	}
	return defaultAnonymousUser()
}

// Protect wrapps handlers to verify authentication at the group or route level.
// it does not provide authorization, but ensures the data required to asses
// permissions is present.
func Protect(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ec echo.Context) error {
		// Test against skipper, skip protection if true
		c := &AuthContext{ec}
		store := c.Get(contextStoreKey)
		if store != nil {
			values, ok := store.(*authValues)
			if ok && values.skipper(c) {
				return next(ec)
			}
		}
		// AJAX requests never trigger session validation
		if c.Request().Header.Get("X-Requested-With") == "xmlhttprequest" {
			return protectXHR(c, next)
		}
		// GET requests always trigger session validation
		if c.Request().Method == "GET" {
			return protectGET(c, next)
		}
		// For POST requests, we accept data but require session refresh before subsequent loads
		if c.Request().Method == "POST" {
			return protectPOST(c, next)
		}
		// PUT and DELETE requests do not accept stale sessions because they alter existing data
		if c.Request().Method == "PUT" {
			return protectPOST(c, next)
		}
		// As an aside, it may be wise to delegate this logic to the calling package in the future
		// and is recommended in forks
		if c.Request().Method == "DELETE" {
			return protectDELETE(c, next)
		}
		return echo.NewHTTPError(echo.ErrMethodNotAllowed.Code, "The request scheme is not supported by the server.")
	}
}

func protectXHR(ec echo.Context, next echo.HandlerFunc) error {
	c := &AuthContext{ec}
	user := c.User()
	if !user.IsAuthenticated {
		return echo.NewHTTPError(echo.ErrUnauthorized.Code, echo.ErrUnauthorized.Message)
	}
	return next(ec)
}

func protectGET(ec echo.Context, next echo.HandlerFunc) error {
	c := &AuthContext{ec}
	user := c.User()
	if !user.IsAuthenticated || user.IsStale {
		return IdentityProviderRedirect(ec)
	}
	return next(ec)
}

func protectPOST(ec echo.Context, next echo.HandlerFunc) error {
	c := &AuthContext{ec}
	user := c.User()
	if !user.IsAuthenticated {
		return echo.NewHTTPError(echo.ErrUnauthorized.Code, echo.ErrUnauthorized.Message)
	}
	if user.IsStale {
		defer ExpireSession(ec)
	}
	return next(ec)
}

func protectPUT(ec echo.Context, next echo.HandlerFunc) error {
	c := &AuthContext{ec}
	user := c.User()
	if !user.IsAuthenticated {
		return echo.NewHTTPError(echo.ErrUnauthorized.Code, echo.ErrUnauthorized.Message)
	}
	if user.IsStale {
		defer ExpireSession(ec)
	}
	return next(ec)
}

func protectDELETE(ec echo.Context, next echo.HandlerFunc) error {
	c := &AuthContext{ec}
	user := c.User()
	if !user.IsAuthenticated {
		return echo.NewHTTPError(echo.ErrUnauthorized.Code, echo.ErrUnauthorized.Message)
	}
	if user.IsStale {
		defer ExpireSession(ec)
	}
	return echo.NewHTTPError(echo.ErrUnauthorized.Code, echo.ErrUnauthorized.Message)
}

// ExpireSession is used to unauthenticate the user
func ExpireSession(c echo.Context) {
	sess := session.Default(c)
	sess.Set(sessionStoreKey, nil)
	sess.Save()
}

// IdentityProviderRedirect sets a nonce for a session and redirects to the Authority
func IdentityProviderRedirect(ec echo.Context) error {
	sess := session.Default(ec)
	nonce := uuid.New().String()
	sess.Set("auth_nonce", nonce)
	sess.Save()

	store := ec.Get(contextStoreKey)
	if store == nil {
		return echo.NewHTTPError(500, "Misconfigured pipeline.")
	}
	values, ok := store.(*authValues)
	if !ok {
		return echo.NewHTTPError(500, "Misconfigured pipeline.")
	}
	redirectURI := values.redirectURI
	authEndpoint := fmt.Sprintf(values.authority, redirectURI, redirectURI, nonce)

	return ec.Redirect(http.StatusFound, authEndpoint)
}

// IdentityProviderURL returns the url for the authority
func IdentityProviderURL(ec echo.Context) (string, error) {
	sess := session.Default(ec)
	nonce := uuid.New().String()
	sess.Set("auth_nonce", nonce)
	sess.Save()

	store := ec.Get(contextStoreKey)
	if store == nil {
		return "", errors.New("no context from which to determine the authentication endpoint")
	}
	values, ok := store.(*authValues)
	if !ok {
		return "", errors.New("no context from which to determine the authentication endpoint")
	}
	redirectURI := ec.Scheme() + "://" + ec.Request().Host

	return fmt.Sprintf(values.authority, redirectURI, redirectURI, nonce), nil
}

func defaultRedirectFunc(c echo.Context) string {
	request := c.Request()
	return c.Scheme() + "://" + request.Host + request.URL.Path
}

func defaultAnonymousUser() *User {
	return &User{
		LastName:        "",
		FirstName:       "",
		Username:        "",
		Email:           "",
		Groups:          []string{},
		IsAuthenticated: false,
		IsStale:         true,
	}
}
