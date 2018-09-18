package authenticate

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mendsley/gojwk"
)

var configURL = "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration"

func getKeysFromMicrosoft(tenantID string) ([]gojwk.Key, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	tenantConfig := fmt.Sprintf(configURL, tenantID)

	res, err := httpClient.Get(tenantConfig)
	if err != nil {
		return nil, err
	}

	byt, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(byt, &data)
	if err != nil {
		return nil, err
	}

	res, err = httpClient.Get(data["jwks_uri"].(string))
	if err != nil {
		return nil, err
	}

	byt, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	var keys struct {
		Keys []gojwk.Key `json:"keys"`
	}
	err = json.Unmarshal(byt, &keys)

	if err != nil {
		return nil, err
	}

	return keys.Keys, nil
}

func (a *ActiveDirectory) getKey(kid string) (*rsa.PublicKey, error) {
	// Cycle through our saved keys
	for _, key := range a.Keys {
		if key.Kid == kid {
			pubKey, err := key.DecodePublicKey()
			if err != nil {
				return nil, err
			}
			return pubKey.(*rsa.PublicKey), nil
		}
	}

	// Microsoft cycles keys daily. Check for new keys
	keys, err := getKeysFromMicrosoft(a.TenantID)
	if err != nil {
		return nil, err
	}

	a.Keys = keys

	for _, key := range a.Keys {
		if key.Kid == kid {
			pubKey, err := key.DecodePublicKey()
			if err != nil {
				return nil, err
			}
			return pubKey.(*rsa.PublicKey), nil
		}
	}

	return nil, fmt.Errorf("No key found for kid: %s", kid)
}
