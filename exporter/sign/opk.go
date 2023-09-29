package sign

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
)

type OPKSigner struct {
	provider parties.OpenIdProvider
}

func NewOPKSigner(provider parties.OpenIdProvider) *OPKSigner {
	return &OPKSigner{provider: provider}
}

func (s *OPKSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash := s256(data)
	hashHex := hex.EncodeToString(hash)

	tokSigner, err := pktoken.NewSigner("", "ES256", true, map[string]any{"att": hashHex})
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
	return nil
}

func (s *OPKSigner) KeyID() (string, error) {
	return "OPK", nil
}
func s256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
