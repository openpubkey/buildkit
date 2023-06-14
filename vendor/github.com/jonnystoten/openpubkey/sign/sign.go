package sign

import (
	"context"
	"encoding/base64"
	"fmt"

	json "github.com/gibson042/canonicaljson-go"
	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/jonnystoten/openpubkey/oidc"
	"github.com/jonnystoten/openpubkey/opk"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func SignInTotoStatements(_ context.Context, stmts []in_toto.Statement, iss string) ([]dsse.Envelope, error) {
	provider := oidc.Providers[iss]
	if provider == nil {
		return nil, fmt.Errorf("unkown oidc provider %s", iss)
	}
	envs := make([]dsse.Envelope, 0)
	for _, stmt := range stmts {
		payload, err := json.Marshal(stmt)
		if err != nil {
			return nil, err
		}
		jwt, err := opk.SignedOpenPubKey(&payload, provider)
		if err != nil {
			return nil, err
		}
		sig, err := json.Marshal(jwt)
		if err != nil {
			return nil, err
		}
		envs = append(envs, dsse.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     base64.StdEncoding.EncodeToString(payload),
			Signatures: []dsse.Signature{{
				Sig: base64.StdEncoding.EncodeToString(sig),
			}},
		})
	}
	return envs, nil
}
