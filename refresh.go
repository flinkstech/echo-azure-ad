package authenticate

import (
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
	RefreshTokenResponse struct {
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Resource     string `json:"resource"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
)

func (a *activeDirectory) refreshExpiry(refreshToken string) (string, string, int64, error) {
	var permissions string
	if a.ExtraPermissions == "" {
		permissions = "User.Read Group.Read.All offline_access"
	} else {
		permissions = "User.Read Group.Read.All" + fmt.Sprintf(" %s", a.ExtraPermissions)
	}
	refreshFormData, err := json.Marshal(&refreshTokenPostJSON{
		ClientID:     a.ClientID,
		Scope:        permissions,
		Tenant:       a.TenantID,
		RedirectURI:  a.RedirectURI,
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
		ClientSecret: a.ClientSecret,
	})
	if err != nil {
		return "", "", 0, err
	}
	values := url.Values{}
	var data map[string]interface{}
	if err := json.Unmarshal(refreshFormData, &data); err != nil {
		return "", "", 0, err
	}
	for key, value := range data {
		values.Add(key, value.(string))
	}

	refreshEndpoint := fmt.Sprintf(accessTokenURI, a.TenantID)

	req, err := http.NewRequest("POST", refreshEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(values.Encode())))

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}

	byt, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return "", "", 0, err
	}

	responseData := &accessTokenResponse{}
	err = json.Unmarshal(byt, &responseData)
	if err != nil {
		return "", "", 0, err
	}

	// Prepare data for refresh
	var formData refreshTokenPostJSON
	if err := json.Unmarshal(refreshFormData, &formData); err != nil {
		return "", "", 0, err
	}
	formData.RefreshToken = responseData.RefreshToken

	return responseData.AccessToken, responseData.RefreshToken, responseData.ExpiresIn, nil
}
