package sign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/jonnystoten/openpubkey/opk"
)

type ECDSASignerVerifier struct {
	priv *ecdsa.PrivateKey
}

func NewECDSASignerVerifier(priv *ecdsa.PrivateKey) *ECDSASignerVerifier {
	return &ECDSASignerVerifier{priv}
}

func (sv *ECDSASignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	h := s256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, sv.priv, h)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (sv *ECDSASignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	h := s256(data)
	if !ecdsa.VerifyASN1(&sv.priv.PublicKey, h, sig) {
		return fmt.Errorf("cannot verify")
	}
	return nil
}

func (sv *ECDSASignerVerifier) Public() crypto.PublicKey {
	return sv.priv.Public()
}

func (sv *ECDSASignerVerifier) KeyID() (string, error) {
	pem, err := opk.PubToPem(sv.Public())
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

func s256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
