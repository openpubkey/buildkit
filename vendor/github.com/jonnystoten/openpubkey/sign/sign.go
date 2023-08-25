package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/jonnystoten/openpubkey/oidc"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func SignInTotoStatements(ctx context.Context, stmts []in_toto.Statement, iss string) ([]dsse.Envelope, error) {
	provider := oidc.Providers[iss]
	if provider == nil {
		return nil, fmt.Errorf("unkown oidc provider %s", iss)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	opkSigner := NewOPKSignerVerifier(NewECDSASignerVerifier(privKey), provider)
	s, err := dsse.NewEnvelopeSigner(opkSigner)
	if err != nil {
		return nil, fmt.Errorf("error creating dsse signer: %w", err)
	}

	envs := make([]dsse.Envelope, 0)
	for _, stmt := range stmts {
		payload, err := json.Marshal(stmt)
		if err != nil {
			return nil, err
		}

		env, err := s.SignPayload(ctx, "application/vnd.in-toto+json", payload)
		if err != nil {
			return nil, err
		}

		envs = append(envs, *env)
	}
	return envs, nil
}
