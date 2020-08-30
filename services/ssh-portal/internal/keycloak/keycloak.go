package keycloak

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Client is a keycloak client.
type Client struct {
	baseURL          *url.URL
	authServerSecret string
	log              *zap.Logger
}

// New creates a new keycloak client.
func New(baseURL, authServerSecret string, log *zap.Logger) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL:          u,
		authServerSecret: authServerSecret,
	}, nil
}

// UserTokenReq is the request to keycloak for the user token
type UserTokenReq struct {
	GrantType        string `json:"grant_type"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	RequestedSubject string `json:"requested_subject"`
}

// UserToken returns a JWT token for the given userID.
func (c *Client) UserToken(userID *uuid.UUID) (string, error) {
	reqBytes, err := json.Marshal(UserTokenReq{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         "auth-server",
		ClientSecret:     c.authServerSecret,
		RequestedSubject: userID.String(),
	})
	if err != nil {
		return "", err
	}
	c.log.Debug("keycloak request body", zap.ByteString("reqBytes", reqBytes))
	reqData := bytes.NewBuffer(reqBytes)
	hc := http.Client{
		Timeout: 10 * time.Second,
	}
	tokenURL, err := url.Parse(c.baseURL.String())
	if err != nil {
		return "", err
	}
	tokenURL.Path = path.Join(tokenURL.Path,
		`/auth/realms/lagoon/protocol/openid-connect/token`)
	resp, err := hc.Post(tokenURL.String(), "application/json", reqData)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)

	return string(respBody), err
}
