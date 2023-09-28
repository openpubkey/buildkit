package sign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type ECDSASigner struct {
	priv   *ecdsa.PrivateKey
	pubJWK jwk.Key
}

func NewECDSASigner(priv *ecdsa.PrivateKey) (*ECDSASigner, error) {
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		return nil, err
	}
	return &ECDSASigner{priv, pub}, nil
}

func (s *ECDSASigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	h := s256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, h)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *ECDSASigner) Public() crypto.PublicKey {
	return s.priv.Public()
}

func (s *ECDSASigner) KeyID() (string, error) {
	return s.pubJWK.KeyID(), nil
}

func s256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
