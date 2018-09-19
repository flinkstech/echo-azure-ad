package authenticate

import (
	"encoding/gob"
	"fmt"
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
		RedirectURI  string
		Skipper      func(echo.Context) bool
	}

	// ActiveDirectory is like AuthSettings but with methods and stores internal states
	ActiveDirectory struct {
		ClientID       string
		TenantID       string
		ClientSecret   string
		RedirectURI    string
		Skipper        func(echo.Context) bool
		sessionStoreID string
		Keys           []gojwk.Key
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

	sessionStore struct {
		IDToken *activeDirectoryClaims
		Groups  []MemberGroup
	}
)

// Init : returns an ActiveDirectory struct to be used outside the package
func Init(settings *AuthSettings) *ActiveDirectory {
	auth := &ActiveDirectory{}
	auth.ClientID = settings.ClientID
	auth.TenantID = settings.TenantID
	auth.RedirectURI = settings.RedirectURI
	auth.ClientSecret = settings.ClientSecret
	auth.sessionStoreID = uuid.New().String()
	if settings.Skipper == nil {
		auth.Skipper = func(c echo.Context) bool { return false }
	} else {
		auth.Skipper = settings.Skipper
	}
	gob.Register(sessionStore{})
	gob.Register(activeDirectoryClaims{})
	gob.Register(MemberGroup{})
	return auth
}

// DangerouslyRetrieveSessionStoreKey returns the key to auth session data
func (a *ActiveDirectory) DangerouslyRetrieveSessionStoreKey() string {
	return a.sessionStoreID
}

// ActiveDirectoryAuthentication is echo middleware
func (a *ActiveDirectory) ActiveDirectoryAuthentication(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if a.sessionIsAuthenticated(c) || a.Skipper(c) {
			return next(c)
		}

		r := c.Request()

		if r.Method == "GET" {
			sess := session.Default(c)
			nonce := uuid.New().String()
			sess.Set("auth_nonce", nonce)
			sess.Save()
			return a.redirectToIdentityProvider(c, nonce)
		}

		if r.Method == "POST" {
			var form stsPostData
			if err := c.Bind(&form); err != nil {
				// If we can't bind, the POST was not from the authentication authority
				return c.String(http.StatusUnauthorized, "Unauthorized")
			}

			token, err := jwt.ParseWithClaims(form.IDToken, &activeDirectoryClaims{}, func(token *jwt.Token) (interface{}, error) {
				return a.getKey(token.Header["kid"].(string))
			})
			if err != nil {
				msg := "Failed to parse claims from id_token"
				return c.String(http.StatusInternalServerError, msg)
			}

			if claims, ok := token.Claims.(*activeDirectoryClaims); ok && token.Valid {
				// The token signature has been verified, but check that the nonce was
				// generated by us to fend against claim impersonation
				sess := session.Default(c)
				sentNonce, _ := uuid.Parse(sess.Get("auth_nonce").(string))
				receivedNonce, _ := uuid.Parse(claims.Nonce)
				if sentNonce == receivedNonce {
					a.authenticateSession(c, claims, form.Code)
					return next(c)
				}
			}

			msg := "Authentication failed"
			return c.String(http.StatusUnauthorized, msg)
		}

		msg := "Unauthorized"
		return c.String(http.StatusUnauthorized, msg)
	}
}

// MemberOfGroup accepts a group name, and returns true if the authenticated user
// belongs to the group, false in any other case.
func (a *ActiveDirectory) MemberOfGroup(c echo.Context, displayName string) bool {
	sess := session.Default(c)
	store := sess.Get(a.sessionStoreID)
	if store == nil {
		return false
	}

	storeData := store.(sessionStore)

	for _, group := range storeData.Groups {
		if group.DisplayName == displayName {
			return true
		}
	}
	return false
}

// MemberGroups returns the full list of group display names assocaited to the user
func (a *ActiveDirectory) MemberGroups(c echo.Context) []string {
	sess := session.Default(c)
	store := sess.Get(a.sessionStoreID)
	if store == nil {
		return []string{}
	}

	storeData := store.(sessionStore)

	names := []string{}

	for _, group := range storeData.Groups {
		names = append(names, group.DisplayName)
	}

	return names
}

// UserClaims returns a truncated list of user claims
func (a *ActiveDirectory) UserClaims(c echo.Context) interface{} {
	sess := session.Default(c)
	store := sess.Get(a.sessionStoreID)
	if store == nil {
		return nil
	}

	storeData := store.(sessionStore)

	return struct {
		FamilyName string
		GivenName  string
		Username   string
		Email      string
	}{
		FamilyName: storeData.IDToken.FamilyName,
		GivenName:  storeData.IDToken.GivenName,
		Username:   storeData.IDToken.Name,
		Email:      storeData.IDToken.UniqueName,
	}
}

// SignOut redirects the client to the signout URL, which then performs a subsequent redirect
func (a *ActiveDirectory) SignOut(c echo.Context, redirectURI string) error {
	signOutURL := "https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s"
	return c.Redirect(http.StatusFound, fmt.Sprint(signOutURL, a.TenantID, redirectURI))
}

func (a *ActiveDirectory) sessionIsAuthenticated(c echo.Context) bool {
	sess := session.Default(c)
	store := sess.Get(a.sessionStoreID)
	if store == nil {
		return false
	}

	storeData := store.(sessionStore)

	expiresAt := storeData.IDToken.StandardClaims.ExpiresAt
	if expiresAt > time.Now().Unix() {
		return true
	}

	return false
}

func (a *ActiveDirectory) authenticateSession(c echo.Context, claims *activeDirectoryClaims, code string) {
	sess := session.Default(c)
	groups, _ := a.getGroups(code)
	sess.Set(a.sessionStoreID, &sessionStore{
		IDToken: claims,
		Groups:  groups,
	})
	sess.Save()
}

func (a *ActiveDirectory) redirectToIdentityProvider(c echo.Context, nonce string) error {
	//r := c.Request()
	//requestURL := c.Scheme() + "://" + r.Host + r.URL.Path

	fstring := ("https://login.microsoftonline.com/%s/oauth2/authorize?" +
		"client_id=%s&response_type=id_token+code&redirect_uri=%s" +
		"&response_mode=form_post&scope=openid&nonce=%s")

	authEndpoint := fmt.Sprintf(fstring, a.TenantID, a.ClientID, a.RedirectURI, nonce)

	return c.Redirect(http.StatusFound, authEndpoint)
}
