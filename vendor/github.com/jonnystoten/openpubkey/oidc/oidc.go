package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type GetOIDCToken func(audience string) (*JWT, error)

type Claims struct {
	Audience string `json:"aud"`
}

type OIDCProvider interface {
	Issuer() string
	GetJWT(*Claims) ([]byte, error)
	Verify(jwt []byte) (kid string, err error)
	GetPublicKey(kid string) (*rsa.PublicKey, error)
}

var (
	GithubActionsIssuer = "https://token.actions.githubusercontent.com"
	Providers           = map[string]OIDCProvider{
		GithubActionsIssuer: &GitHubOIDCProvider{},
	}
)

type JWT string

type OIDCDiscoveryResponse struct {
	JWKS_URI string `json:"jwks_uri"`
}

func Verify(jwtBytes []byte, provider OIDCProvider) (kid string, err error) {
	unsafeToken, err := jwt.ParseInsecure(jwtBytes)
	if err != nil {
		return "", fmt.Errorf("could not parse jwt: %w", err)
	}
	if unsafeToken.Issuer() != provider.Issuer() {
		return "", fmt.Errorf("bad issuer")
	}

	jwks, err := GetJWKSFromDiscovery(provider.Issuer())
	if err != nil {
		return "", fmt.Errorf("could not get jwks: %w", err)
	}

	_, err = jwt.Parse(jwtBytes, jwt.WithKeySet(jwks), jwt.WithAcceptableSkew(1*time.Minute))
	if err != nil {
		return "", fmt.Errorf("could not verify jwt with jwks: %w", err)
	}

	parsedJWS, err := jws.Parse(jwtBytes)
	if err != nil {
		panic(err)
	}

	kid = parsedJWS.Signatures()[0].ProtectedHeaders().KeyID()
	return kid, nil
}

func GetJWKSFromDiscovery(issuerUrl string) (jwk.Set, error) {
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

	return jwks, nil
}

func GetOIDCPublicKey(issuerUrl string, kid string) (*rsa.PublicKey, error) {
	jwks, err := GetJWKSFromDiscovery(issuerUrl)
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
