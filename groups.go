package authenticate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type (
	accessTokenPostJSON struct {
		ClientID     string `json:"client_id"`
		Scope        string `json:"scope"`
		Tenant       string `json:"tenant"`
		RedirectURI  string `json:"redirect_uri"`
		GrantType    string `json:"grant_type"`
		Code         string `json:"code"`
		ClientSecret string `json:"client_secret"`
	}

	memberGroupsPostJSON struct {
		SecurityEnabledOnly bool `json:"securityEnabledOnly"`
	}

	groupFromIDPostJSON struct {
		IDs   []string `json:"ids"`
		Types []string `json:"types"`
	}

	// MemberGroups is used for unmarshalling a Graph API response
	MemberGroups struct {
		Values []MemberGroup `json:"value"`
	}

	// MemberGroup captures data from a Group Directory Object.
	// Other properties exist, but don't necessarily pertain to authorization
	MemberGroup struct {
		DataType        string `json:"@odata.type"`
		Description     string `json:"description"`
		DisplayName     string `json:"displayName"`
		SecurityEnabled bool   `json:"securityEnabled"`
	}
)

var accessTokenURI = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
var memberGroupsURI = "https://graph.microsoft.com/v1.0/me/getMemberGroups"
var objectByIDURI = "https://graph.microsoft.com/v1.0/directoryObjects/getByIds"

func (a *activeDirectory) getGroups(code string) ([]MemberGroup, error) {
	accessToken, err := a.getAccessToken(code)
	if err != nil {
		return nil, err
	}

	memberGroupIDs, err := a.getMemberGroupIDs(accessToken)
	if err != nil {
		return nil, err
	}

	return getGroupsByID(accessToken, memberGroupIDs)
}

func (a *activeDirectory) getMemberGroupIDs(accessToken string) ([]string, error) {
	requestJSON, err := json.Marshal(&memberGroupsPostJSON{
		SecurityEnabledOnly: false,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", memberGroupsURI, bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	byt, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	var structuredData struct {
		Values []string `json:"value"`
	}
	err = json.Unmarshal(byt, &structuredData)
	if err != nil {
		return nil, err
	}

	return structuredData.Values, nil
}

func (a *activeDirectory) getAccessToken(code string) (string, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	tokenGrant := fmt.Sprintf(accessTokenURI, a.TenantID)

	requestJSON, err := json.Marshal(&accessTokenPostJSON{
		ClientID:     a.ClientID,
		Scope:        "User.Read Group.Read.All",
		Tenant:       a.TenantID,
		RedirectURI:  a.RedirectURI,
		GrantType:    "authorization_code",
		Code:         code,
		ClientSecret: a.ClientSecret,
	})
	if err != nil {
		return "", err
	}

	values := url.Values{}
	var data map[string]interface{}
	if err = json.Unmarshal([]byte(requestJSON), &data); err != nil {
		return "", err
	}
	for key, value := range data {
		values.Add(key, value.(string))
	}

	req, err := http.NewRequest("POST", tokenGrant, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(values.Encode())))

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	byt, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(byt, &data)
	if err != nil {
		return "", err
	}

	accessToken := data["access_token"]

	return accessToken.(string), nil
}

func getGroupsByID(accessToken string, groupIDs []string) ([]MemberGroup, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	requestJSON := &groupFromIDPostJSON{
		IDs:   groupIDs,
		Types: []string{"group"},
	}

	jsonData, err := json.Marshal(requestJSON)
	if err != nil {
		return nil, err
	}

	var jsonStr = []byte(jsonData)
	req, err := http.NewRequest("POST", objectByIDURI, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	byt, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	var memberGroups MemberGroups
	err = json.Unmarshal(byt, &memberGroups)
	if err != nil {
		return nil, err
	}

	return memberGroups.Values, nil
}
