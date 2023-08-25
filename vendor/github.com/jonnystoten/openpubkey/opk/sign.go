package opk

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/jonnystoten/openpubkey/gq"
	"github.com/jonnystoten/openpubkey/oidc"
)

func SignedOpenPubKey(payload []byte, sig []byte, pubKey crypto.PublicKey, signer Signer, provider oidc.OIDCProvider) (*JWS, error) {
	pem, err := PubToPem(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PEM: %w", err)
	}

	rz := make([]byte, 32)
	_, err = rand.Read(rz)
	if err != nil {
		return nil, err
	}

	cic := NewCIC("ES256", pem, rz, sig)

	claims := &oidc.Claims{
		Audience: cic.Hash(),
	}
	jwt, err := provider.GetJWT(claims)
	if err != nil {
		return nil, err
	}

	kid, err := provider.Verify(jwt)
	if err != nil {
		return nil, err
	}

	pub, err := provider.GetPublicKey(kid)
	if err != nil {
		return nil, err
	}

	proof, err := gq.ProveJWTSignature(string(jwt), pub, 256)
	if err != nil {
		return nil, err
	}

	return NewOpenPubKey(jwt, signer, cic, proof), nil
}
