package sign

import (
	"context"
	"crypto"
	"encoding/json"

	"github.com/jonnystoten/openpubkey/internal/utils"
	"github.com/jonnystoten/openpubkey/oidc"
	"github.com/jonnystoten/openpubkey/opk"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type OPKSignerVerifier struct {
	inner    dsse.SignerVerifier
	provider oidc.OIDCProvider
}

func NewOPKSignerVerifier(inner dsse.SignerVerifier, provider oidc.OIDCProvider) *OPKSignerVerifier {
	return &OPKSignerVerifier{inner: inner, provider: provider}
}

func (sv *OPKSignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	sig, err := sv.inner.Sign(ctx, data)
	if err != nil {
		return nil, err
	}

	opkJWS, err := opk.SignedOpenPubKey(data, sig, sv.inner.Public(), sv.inner, sv.provider)
	if err != nil {
		return nil, err
	}
	opkSig, err := json.Marshal(opkJWS)
	if err != nil {
		return nil, err
	}

	return opkSig, nil
}

func (sv *OPKSignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	opkJWS := new(opk.JWS)
	err := json.Unmarshal(sig, opkJWS)
	if err != nil {
		return err
	}

	err = opk.VerifyOPK(opkJWS, sv.provider)
	if err != nil {
		return err
	}

	protected := opkJWS.Signatures[1].Protected
	protectedJSON, err := utils.Base64Decode(protected)
	if err != nil {
		return err
	}

	cic := new(opk.CIC)
	err = json.Unmarshal(protectedJSON, cic)
	if err != nil {
		return err
	}

	err = sv.inner.Verify(ctx, data, cic.Signature)
	if err != nil {
		return err
	}

	return nil
}

func (sv *OPKSignerVerifier) Public() crypto.PublicKey {
	return sv.inner.Public()
}

func (sv *OPKSignerVerifier) KeyID() (string, error) {
	return "OPK", nil
}
