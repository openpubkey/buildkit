package opk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/jonnystoten/openpubkey/internal/utils"
	"github.com/jonnystoten/openpubkey/types"
	"github.com/lestrrat-go/jwx/v2/jws"
	"golang.org/x/crypto/sha3"
)

type JWS struct {
	Payload    types.Base64Encoded `json:"payload"`
	Signatures []JWSignature       `json:"signatures"`
}

type JWSignature struct {
	Protected types.Base64Encoded `json:"protected"`
	Signature types.Base64Encoded `json:"signature"`
}

type CIC struct {
	Algorithm   string `json:"alg"`
	PublicKey   []byte `json:"pub"`
	RandomNoise []byte `json:"rz"`
	Signature   []byte `json:"sig"`
}

type Signer interface {
	Sign(ctx context.Context, data []byte) ([]byte, error)
}

func NewKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func PubToPem(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: b,
		},
	), nil
}

func PemToPub(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block from %q", pemBytes)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func PrivToPem(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	))
}

func SHA512(things ...[]byte) []byte {
	sha := sha512.New()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func SHA3(things ...[]byte) []byte {
	sha := sha3.New512()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func SHA256(things ...[]byte) []byte {
	sha := sha256.New()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func NewCIC(alg string, pub, noise, sig []byte) *CIC {
	return &CIC{
		Algorithm:   alg,
		PublicKey:   pub,
		RandomNoise: noise,
		Signature:   sig,
	}
}

func (c *CIC) Hash() string {
	sha := SHA3([]byte(c.Algorithm), c.PublicKey, c.RandomNoise, c.Signature)
	return hex.EncodeToString(sha)
}

type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
}

func NewVerifier(pub *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return &ECDSAVerifier{
		publicKey: pub,
	}, nil
}

func (e ECDSAVerifier) Verify(signature, message []byte) error {
	if e.publicKey == nil {
		return errors.New("no public key set for ECDSAVerifier")
	}

	digest := SHA256(message)

	if !ecdsa.VerifyASN1(e.publicKey, digest, signature) {
		return errors.New("invalid signature for ECDSAVerifier")
	}
	return nil
}

func NewOpenPubKey(jwtBytes []byte, sv Signer, cic *CIC, gqProof string) *JWS {
	var header, payload types.Base64Encoded
	header, payload, _, err := jws.SplitCompact(jwtBytes)
	if err != nil {
		panic(err)
	}
	opkHeaderJSON, _ := utils.JSONMarshal(cic)
	opkHeader := utils.Base64Encode(opkHeaderJSON)
	signingPayload := bytes.Join([][]byte{opkHeader, payload}, []byte("."))
	opkSig, err := sv.Sign(context.TODO(), signingPayload)

	if err != nil {
		panic(err)
	}
	return &JWS{
		Payload: payload,
		Signatures: []JWSignature{
			{
				Protected: header,
				Signature: []byte(gqProof),
			},
			{
				Protected: opkHeader,
				Signature: utils.Base64Encode(opkSig),
			},
		},
	}
}
