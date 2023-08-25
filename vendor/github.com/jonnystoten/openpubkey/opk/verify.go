package opk

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/jonnystoten/openpubkey/gq"
	"github.com/jonnystoten/openpubkey/internal/utils"
	"github.com/jonnystoten/openpubkey/oidc"
)

func VerifyOPK(jws *JWS, provider oidc.OIDCProvider) error {
	payload, opkSignature := jws.Payload, jws.Signatures[1]

	cic, err := VerifyOPKSignature(opkSignature, payload)
	if err != nil {
		return fmt.Errorf("failed to verify opk signature: %w", err)
	}
	fmt.Println("Verified OPK signature")
	err = VerifyOIDCSignature(jws.Signatures[0], payload, provider)
	if err != nil {
		return fmt.Errorf("failed to verify oidc signature: %w", err)
	}
	err = verifyNonce(cic, payload)
	if err != nil {
		return fmt.Errorf("failed to verify nonce: %w", err)
	}
	fmt.Println("Verified signed payload matches")
	return nil
}

func VerifyOPKSignature(sigWrapper JWSignature, payload []byte) (*CIC, error) {
	protectedJSON, err := utils.Base64Decode(sigWrapper.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode protected: %w", err)
	}

	var protected CIC
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode our protected: %w", err)
	}

	if protected.Algorithm != "ES256" {
		return nil, fmt.Errorf("expected ES256 alg, got %q", protected.Algorithm)
	}

	pubKeyPEM := protected.PublicKey
	pubKey, err := PemToPub(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode our public key: %w", err)
	}

	sig, err := utils.Base64Decode(sigWrapper.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode our signature: %w", err)
	}

	verifier, err := NewVerifier(pubKey.(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to LoadECDSAVerifier: %w", err)
	}

	signingInput := bytes.Join([][]byte{sigWrapper.Protected, payload}, []byte("."))

	err = verifier.Verify(sig, signingInput)
	if err != nil {
		return nil, fmt.Errorf("failed to verify our signature: %w", err)
	}

	fmt.Println("Verified signing key in OPK was used to sign OPK payload")

	return &protected, nil
}

type Identity struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

func VerifyOIDCSignature(sigWrapper JWSignature, payloadBytes []byte, provider oidc.OIDCProvider) error {
	protectedJSON, err := utils.Base64Decode(sigWrapper.Protected)
	if err != nil {
		return fmt.Errorf("failed to base64 decode protected: %w", err)
	}
	//log.Debugln("Decoded protected: %s\n", string(protectedJSON))
	var protected map[string]string
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return fmt.Errorf("failed to json decode their protected: %w", err)
	}
	//log.Debugln("Unmarshalled protected: %s\n", protected)

	if protected["alg"] != "RS256" {
		return fmt.Errorf("expected RS256 alg")
	}
	//log.Debugln("Got alg %s\n", protected["alg"])
	payloadJSON, err := utils.Base64Decode(payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}
	//log.Debugln("Decoded payload: %s\n", string(payloadJSON))
	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}

	issuer := payload["iss"].(string)
	//log.Debugln("Got issuer %s\n", issuer)

	if issuer != provider.Issuer() {
		return fmt.Errorf("iss claim doesn't match, expected %q, got %q", provider.Issuer(), issuer)
	}

	pubKey, err := provider.GetPublicKey(protected["kid"])
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	proof, err := gq.DecodeProof(string(sigWrapper.Signature))
	if err != nil {
		return fmt.Errorf("failed to decode GQ proof: %w", err)
	}

	signingInput := bytes.Join([][]byte{sigWrapper.Protected, payloadBytes}, []byte("."))

	validProof := proof.Validate()
	if !validProof {
		return fmt.Errorf("invalid GQ proof")
	}

	verified := proof.Verify(signingInput, pubKey)
	if !verified {
		return fmt.Errorf("failed to verify GQ proof")
	}

	fmt.Println("Verified OIDC payload was signed by", issuer)

	return nil
}

func verifyNonce(cic *CIC, payloadBytes []byte) error {
	payloadJSON, err := utils.Base64Decode(payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	//log.Debugln("Unmarshalled payload")
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}
	//log.Debugln("Verifying nonce in OIDC payload")
	nonce := payload["aud"].(string)

	if nonce != cic.Hash() {
		return fmt.Errorf("nonce doesn't match")
	}

	fmt.Println("Verified nonce in OIDC payload matches header")
	return nil
}
