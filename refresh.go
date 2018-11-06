package authenticate

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type (
	RefreshTokenResponse struct {
		TokenType    string `json:"token_type"`
		ExpiresIn    string `json:"expires_in"`
		ExpiresOn    string `json:"expires_on"`
		Resource     string `json:"resource"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
)

func refreshExpiry(refreshToken, refreshEndpoint string) (string, string, string, error) {
	refreshTokenURI := fmt.Sprintf(refreshEndpoint, refreshToken)
	req, err := http.NewRequest("POST", refreshTokenURI, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return "", "", "", err
	}

	byt, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return "", "", "", err
	}

	responseData := &RefreshTokenResponse{}
	err = json.Unmarshal(byt, &responseData)
	if err != nil {
		return "", "", "", err
	}

	return responseData.AccessToken, responseData.RefreshToken, responseData.ExpiresOn, nil
}
