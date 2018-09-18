# Active Directory Authentication middleware package
##### Assumes the importing project uses echo, echo-session
#### Uses v2.0 endpoint for OpenIdConnect, and v1.0 of Microsoft Graph API

## Usage

Initialize with:

auth2 := authenticate.Init(&authenticate.AuthSettings{
		ClientID:     ,
		TenantID:     ,
		ClientSecret: ,
		RedirectURI:  ,
		Skipper:	  , (Optional)
	})

NOTE: All redirect URLs in a given flow must be match, and included in the Active Directory app registration
The present implementation accepts one redirecturi which must accept a post request

Methods:
 - ActiveDirectoryAuthentication (echo middleware)
 - MemberOfGroup(groupname) returns boolean if session use is in group
 - SignOut(echo.Context, redirectURI) Signs user out, ultimately redirecting to the provided URI

### On authorization
The middleware will authenticate requests on routes to which it is attached. It is up to the logic of the handler to then verify that the authenticated session's user has the right permissions. To do this, handlers for routes with restricted permissions should receive a reference to the initialized auth object to call its methods.

## Notes
 DangerouslyRetrieveSessionStoreKey() exposes the key where session is stored,
 granting access to the raw id token and group objects to the outside application.
 Any use of this is probably a sign that this package should be extended so the
 resulting functionality can be re-used.
