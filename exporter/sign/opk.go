package sign

import (
	"context"
	"crypto"
	"encoding/base64"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
)

type OPKSigner struct {
	inner    *ECDSASigner
	provider parties.OpenIdProvider
}

func NewOPKSigner(inner *ECDSASigner, provider parties.OpenIdProvider) *OPKSigner {
	return &OPKSigner{inner: inner, provider: provider}
}

func (s *OPKSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	sig, err := s.inner.Sign(ctx, data)
	if err != nil {
		return nil, err
	}

	tokSigner, err := pktoken.LoadSigner("", nil, s.inner.priv, "ES256", true, map[string]any{"sig": base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return nil, err
	}
	opkClient := parties.OpkClient{Op: s.provider, Signer: tokSigner}

	opkSig, err := opkClient.OidcAuth()
	if err != nil {
		return nil, err
	}

	return opkSig, nil
}

// TODO: upgrade to latest secure-systems-lab/go-securesystemslib to fix bug where
// verifier interface must be implemented too
func (sv *OPKSigner) Verify(ctx context.Context, data, sig []byte) error {
	panic("not implemented")
}

func (s *OPKSigner) Public() crypto.PublicKey {
	return s.inner.Public()
}

func (s *OPKSigner) KeyID() (string, error) {
	return "OPK", nil
}
