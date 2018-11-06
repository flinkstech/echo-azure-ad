package authenticate

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
		Resource     string
		Mode         string
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
	}

	sessionStore struct {
		IDToken         *activeDirectoryClaims
		Groups          []MemberGroup
		expiry          int64
		accessToken     string
		refreshToken    string
		refreshEndpoint string
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
	sessionStoreKey = "echo-azure-active-directory-session-key"
	urlTemplate     = ("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?" +
		"client_id=%s&response_type=id_token+code&redirect_uri=%s" +
		"&response_mode=form_post&scope=openid+profile&state=%s&nonce=%s")
	accessURLTemplate = ("https://login.microsoftonline.com/%s/oauth2/v2.0/token?" +
		"client_id=%s&scope=%s&code=%s&redirect_uri=%s&grant_type=authorization_code&client_secret=%s")
	refreshURLTemplate = ("https://login.microsoftonline.com/%s/oauth2/v2.0/token?" +
		"client_id=%s&refresh_token=%s+code&grant_type=refresh_token&client_secret=%s")
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

			if strings.Contains(c.Request().URL.Path, "signin-oidc") {
				var form stsPostData
				err := c.Bind(&form)

				token, err := jwt.ParseWithClaims(
					form.IDToken,
					&activeDirectoryClaims{},
					func(token *jwt.Token) (interface{}, error) {
						a.RedirectURI = ec.Scheme() + "://" + ec.Request().Host + "/signin-oidc"
						return a.getKey(token.Header["kid"].(string))
					})
				if err != nil {
					msg := "id_token invalid or absent"
					return c.String(http.StatusInternalServerError, msg)
				}

				if claims, ok := token.Claims.(*activeDirectoryClaims); ok && token.Valid {
					sess := session.Default(c)
					authNonce := sess.Get("auth_nonce")
					if authNonce == nil {
						// Was able to make this happen by manipulating the cookie
						return c.String(http.StatusUnauthorized, "Authentication failed")
					}
					sentNonce, _ := uuid.Parse(authNonce.(string))
					receivedNonce, _ := uuid.Parse(claims.Nonce)
					if sentNonce == receivedNonce {
						groups, accessToken, refreshToken, _ := a.getGroups(form.Code)
						// Add user to session for future requests
						sess.Set(sessionStoreKey, &sessionStore{
							IDToken:         claims,
							Groups:          groups,
							expiry:          claims.StandardClaims.ExpiresAt,
							accessToken:     accessToken,
							refreshToken:    refreshToken,
							refreshEndpoint: fmt.Sprintf(refreshURLTemplate, settings.TenantID, a.ClientID, "%s", a.ClientSecret),
						})
						sess.Save()

						return ec.HTML(http.StatusOK,
							`<!DOCTYPE HTML5>
							<html><head></head><body>
								<script>
								window.location.href = "`+form.State+`";
								</script>
							</body>
							</html>`)
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

	// Determine validity
	expiresAt := storeData.IDToken.StandardClaims.ExpiresAt

	if expiresAt < time.Now().Unix() {
		accessToken, refreshToken, expiresOn, err := refreshExpiry(storeData.refreshToken, storeData.refreshEndpoint)
		if err != nil {
			fmt.Printf("%s\n", err)
			sess.Set(sessionStoreKey, nil)
			sess.Save()
			return defaultAnonymousUser()
		}
		newExpiry, err := strconv.ParseInt(expiresOn, 10, 64)
		sess.Set(sessionStoreKey, &sessionStore{
			IDToken:         storeData.IDToken, // Unchanged
			Groups:          storeData.Groups,  // Unchanged
			expiry:          newExpiry,
			accessToken:     accessToken,
			refreshToken:    refreshToken,
			refreshEndpoint: storeData.refreshEndpoint, // Unchanged
		})
		sess.Save()
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
		user := c.User()
		if !user.IsAuthenticated {
			return IdentityProviderRedirect(ec)
		}
		return next(ec)
	}
}

// ExpireSession is used to unauthenticate the user
func ExpireSession(c echo.Context) {
	sess := session.Default(c)
	sess.Set(sessionStoreKey, nil)
	sess.Save()
}

// GetAccessToken is used to get the user's access token
func GetAccessToken(c echo.Context) (string, error) {
	sess := session.Default(c)
	store := sess.Get(sessionStoreKey)
	if store == nil {
		return "", errors.New("access token not found")
	}
	storeData, ok := store.(sessionStore)
	if !ok {
		return "", errors.New("access token not found")
	}
	return storeData.accessToken, nil
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
	state := values.redirectURI
	redirectURI := ec.Scheme() + "://" + ec.Request().Host + "/signin-oidc"
	authEndpoint := fmt.Sprintf(values.authority, redirectURI, state, nonce)

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
	state := values.redirectURI
	redirectURI := ec.Scheme() + "://" + ec.Request().Host + "/signin-oidc"
	return fmt.Sprintf(values.authority, redirectURI, state, nonce), nil
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
	}
}
