package gq

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWSignature struct {
	Protected   string         `json:"protected"`
	Unprotected map[string]any `json:"header"`
	Signature   string         `json:"signature"`
}

type JWS struct {
	Payload    string        `json:"payload"`
	Signatures []JWSignature `json:"signatures"`
}

func ReplaceSigWithGQProof(jwt string, pub *rsa.PublicKey, bits int) (string, error) {
	parts := strings.SplitN(jwt, ".", 3)
	header, payload, sig := parts[0], parts[1], parts[2]
	signingPayload := fmt.Sprintf("%v.%v", header, payload)
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", err
	}

	proof := Prove([]byte(signingPayload), signature, pub, bits)
	encodedProof := proof.Encode()

	fullJWS := JWS{
		Payload: payload,
		Signatures: []JWSignature{
			{
				Protected:   header,
				Unprotected: map[string]any{"proof": "gq"},
				Signature:   encodedProof,
			},
		},
	}

	// thing := map[string]any{
	// 	"proof":   encodedProof,
	// 	"header":  header,
	// 	"payload": claims,
	// }

	encoded, err := json.Marshal(fullJWS)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func ProveJWTSignature(jwt string, pub *rsa.PublicKey, bits int) (string, error) {
	parts := strings.SplitN(jwt, ".", 3)
	header, payload, sig := parts[0], parts[1], parts[2]
	signingPayload := fmt.Sprintf("%v.%v", header, payload)
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", err
	}

	proof := Prove([]byte(signingPayload), signature, pub, bits)
	encodedProof := proof.Encode()

	return encodedProof, nil
}

func ValidateGQJWS(gqJwt string, pub *rsa.PublicKey) error {
	var parsed JWS
	err := json.Unmarshal([]byte(gqJwt), &parsed)
	if err != nil {
		return err
	}

	payload := parsed.Payload

	var protected string
	var encodedProof string
	found := false
	for _, sig := range parsed.Signatures {
		headers := sig.Unprotected
		proofHeader, ok := headers["proof"]
		if ok && proofHeader == "gq" {
			found = true
			encodedProof = sig.Signature
			protected = sig.Protected
			break
		}
	}
	if !found {
		panic("cannot find GQ proof signature")
	}

	signingPayload := fmt.Sprintf("%v.%v", protected, payload)

	proof, err := DecodeProof(encodedProof)
	if err != nil {
		return err
	}

	if !proof.Validate() {
		return fmt.Errorf("invalid proof")
	}

	if !proof.Verify([]byte(signingPayload), pub) {
		return fmt.Errorf("unverified proof")
	}

	return nil
}
