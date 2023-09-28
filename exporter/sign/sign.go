package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/parties"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type OIDCProvider string

var GithubActionsOIDC OIDCProvider = "gha"

func SignInTotoStatement(ctx context.Context, stmt intoto.Statement, oidcProvider OIDCProvider) (*dsse.Envelope, error) {
	var provider parties.OpenIdProvider
	switch oidcProvider {
	case GithubActionsOIDC:
		var err error
		provider, err = parties.NewGithubOpFromEnvironment()
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unkown oidc provider %v", oidcProvider)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	ecSigner, err := NewECDSASigner(privKey)
	if err != nil {
		return nil, err
	}
	opkSigner := NewOPKSigner(ecSigner, provider)
	s, err := dsse.NewEnvelopeSigner(opkSigner)
	if err != nil {
		return nil, fmt.Errorf("error creating dsse signer: %w", err)
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}

	env, err := s.SignPayload(ctx, "application/vnd.in-toto+json", payload)
	if err != nil {
		return nil, err
	}

	return env, nil
}
