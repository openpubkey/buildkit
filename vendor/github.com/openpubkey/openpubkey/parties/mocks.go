package parties

import (
	"crypto"
	"crypto/rsa"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

const (
	issuer   = "me"
	audience = "also_me"
)

type MockOpenIdProvider struct {
	alg    jwa.KeyAlgorithm
	signer crypto.Signer
}

func NewMockOpenIdProvider() (*MockOpenIdProvider, error) {
	alg := jwa.RS256
	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	return &MockOpenIdProvider{
		alg:    alg,
		signer: signingKey,
	}, nil
}

func (m *MockOpenIdProvider) RequestTokens(cicHash string) ([]byte, error) {
	token := openid.New()

	token.Set("nonce", cicHash)

	// Required token payload values for OpenID
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set(jwt.ExpirationKey, time.Now().Add(24*time.Hour).Unix())
	token.Set(jwt.SubjectKey, "1234567890")

	// Sign the token with the secret key
	signedToken, err := jwt.Sign(token, jwt.WithKey(m.alg, m.signer))
	if err != nil {
		return nil, err
	}

	return signedToken, nil
}

func (m *MockOpenIdProvider) VerifyPKToken(pkt *pktoken.PKToken, cosPk crypto.PublicKey) (map[string]any, error) {
	return nil, nil
}

func (m *MockOpenIdProvider) PublicKey(idt []byte) (PublicKey, error) {
	return m.signer.Public().(*rsa.PublicKey), nil
}
