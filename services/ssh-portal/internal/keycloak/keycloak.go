package keycloak

import (
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
		log:              log,
	}, nil
}

// UserToken returns a JWT token for the given userID.
func (c *Client) UserToken(userID *uuid.UUID) (string, error) {
	hc := http.Client{
		Timeout: 10 * time.Second,
	}
	tokenURL, err := url.Parse(c.baseURL.String())
	if err != nil {
		return "", err
	}
	tokenURL.Path = path.Join(tokenURL.Path,
		`/auth/realms/lagoon/protocol/openid-connect/token`)
	resp, err := hc.PostForm(tokenURL.String(), url.Values{
		"grant_type":        {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":         {"auth-server"},
		"client_secret":     {c.authServerSecret},
		"requested_subject": {userID.String()},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	return string(respBody), err
}
