package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

type GetOIDCToken func(audience string) (*JWT, error)

type Claims struct {
	Audience string `json:"aud"`
}

type OIDCProvider interface {
	Issuer() string
	GetJWT(*Claims) (*JWT, error)
	GetPublicKey(kid string) (*rsa.PublicKey, error)
}

var (
	GithubActionsIssuer = "https://token.actions.githubusercontent.com"
	Providers           = map[string]OIDCProvider{
		GithubActionsIssuer: &GitHubOIDCProvider{},
	}
)

type JWT struct {
	Count       int
	Value       string
	ParsedToken *jwt.Token
}

type OIDCDiscoveryResponse struct {
	JWKS_URI string `json:"jwks_uri"`
}

func (j *JWT) Parse() error {
	var jwtToken *jwt.Token
	jwt.Parse(j.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		jwtToken = token
		// we don't need a real check here
		return []byte{}, nil
	})
	j.ParsedToken = jwtToken
	return nil
}

func (j *JWT) PrettyPrintClaims() string {
	if claims, ok := j.ParsedToken.Claims.(jwt.MapClaims); ok {
		jsonClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
		}
		return string(jsonClaims)
	}
	return ""
}

func GetOIDCPublicKey(issuerUrl string, kid string) (*rsa.PublicKey, error) {
	//fmt.Println("Fetching OIDC discovery URL: %s", issueUrl)

	discoveryUrl, err := url.JoinPath(issuerUrl, ".well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("failed to construct OIDC discovery URL: %w", err)
	}

	oidcDiscResp, err := http.Get(discoveryUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to OIDC discovery URL: %w", err)
	}

	defer oidcDiscResp.Body.Close()

	if oidcDiscResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %v from OIDC discovery URL", oidcDiscResp.StatusCode)
	}

	var oidcResp OIDCDiscoveryResponse
	decoder := json.NewDecoder(oidcDiscResp.Body)
	err = decoder.Decode(&oidcResp)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode payload: %w", err)
	}

	jwksURI := oidcResp.JWKS_URI
	//log.Debugln("Fetching JWKS URL: %w", jwksURI)

	jwks, err := jwk.Fetch(context.TODO(), jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("couldn't find key %q in JWKS", kid)
	}

	var pubKey rsa.PublicKey
	err = key.Raw(&pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA key: %w", err)
	}
	return &pubKey, nil
}
