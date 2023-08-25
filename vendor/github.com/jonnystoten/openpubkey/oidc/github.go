package oidc

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

func GetEnvironmentVariable(e string) (string, error) {
	value := os.Getenv(e)
	if value == "" {
		return "", fmt.Errorf("missing %s from envrionment", e)
	}
	return value, nil
}

func quitOnErr(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func DefaultOIDCClient(audience string) ActionsOIDCClient {
	tokenURL, err := GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL")
	quitOnErr(err)
	token, err := GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	quitOnErr(err)

	c, err := NewActionsOIDCClient(tokenURL, audience, token)
	quitOnErr(err)

	return c
}

type GitHubOIDCProvider struct {
}

func (p *GitHubOIDCProvider) Issuer() string {
	return GithubActionsIssuer
}

func (p *GitHubOIDCProvider) GetJWT(claims *Claims) ([]byte, error) {
	c := DefaultOIDCClient(claims.Audience)
	jwt, err := c.GetJWT()
	if err != nil {
		return nil, err
	}
	return jwt, nil
}

func (p *GitHubOIDCProvider) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	return GetOIDCPublicKey(p.Issuer(), kid)
}

func (p *GitHubOIDCProvider) Verify(jwt []byte) (kid string, err error) {
	return Verify(jwt, p)
}

type ActionsOIDCClient struct {
	// the url to fetch the jwt
	TokenRequestURL string
	// the audience for the jwt
	Audience string
	// the token used to retrieve the jwt, not the jwt
	RequestToken string
}

// construct a new ActionsOIDCClient
func NewActionsOIDCClient(tokenURL string, audience string, token string) (ActionsOIDCClient, error) {
	c := ActionsOIDCClient{
		TokenRequestURL: tokenURL,
		Audience:        audience,
		RequestToken:    token,
	}
	err := c.BuildTokenURL()
	return c, err
}

// this function uses an ActionsOIDCClient to build the complete URL
// to request a jwt
func (c *ActionsOIDCClient) BuildTokenURL() error {
	parsed_url, err := url.Parse(c.TokenRequestURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	if c.Audience != "" {
		query := parsed_url.Query()
		query.Set("audience", c.Audience)
		parsed_url.RawQuery = query.Encode()
		c.TokenRequestURL = parsed_url.String()
	} else {
		panic("audience is required")
	}

	return nil
}

// retrieve an actions oidc token
func (c *ActionsOIDCClient) GetJWT() ([]byte, error) {
	request, err := http.NewRequest("GET", c.TokenRequestURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+c.RequestToken)

	var httpClient http.Client
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from jwt api: %s", http.StatusText((response.StatusCode)))
	}

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var jwt struct {
		Value string
	}
	err = json.Unmarshal(rawBody, &jwt)

	return []byte(jwt.Value), err
}
