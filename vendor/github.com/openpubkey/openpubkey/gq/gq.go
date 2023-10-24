package gq

import (
	"crypto/rsa"
	"io"
	"math/big"

	"github.com/lestrrat-go/jwx/v2/jws"
	"golang.org/x/crypto/sha3"
)

// Signer allows for creating GQ1 signatures messages.
type Signer interface {
	// Sign creates a GQ1 signature over the given message with the given GQ1 private number.
	Sign(private []byte, message []byte) ([]byte, error)
	// SignJWT creates a GQ1 signature over the JWT token's header/payload with a GQ1 private number derived from the JWT signature.
	//
	// This works because a GQ1 private number can be calculated as the inverse mod n of an RSA signature, where n is the public RSA modulus.
	SignJWT(jwt []byte) ([]byte, error)
}

// Signer allows for verifying GQ1 signatures.
type Verifier interface {
	// Verify verifies a GQ1 signature over a message, using the public identity of the signer.
	Verify(signature []byte, identity []byte, message []byte) bool

	// Compatible with SignJWT, this function verifies the GQ1 signature of the presented JSON Web Token.
	VerifyJWT(jwt []byte) bool
}

// SignerVerifier combines the Signer and Verifier interfaces.
type SignerVerifier interface {
	Signer
	Verifier
}

type signerVerifier struct {
	// n is the RSA public modulus (what Go's RSA lib calls N)
	n *big.Int
	// v is the RSA public exponent (what Go's RSA lib calls E)
	v *big.Int
	// nBytes is the length of n in bytes
	nBytes int
	// vBytes is the length of v in bytes
	vBytes int
	// t is the signature length parameter
	t int
}

// NewSignerVerifier creates a SignerVerifier from the RSA public key of the trusted third-party which creates
// the GQ1 private numbers.
//
// The securityParameter parameter is the level of desired security in bits. 256 is recommended.
func NewSignerVerifier(publicKey *rsa.PublicKey, securityParameter int) SignerVerifier {
	n, v, nBytes, vBytes := parsePublicKey(publicKey)
	t := securityParameter / (vBytes * 8)

	return &signerVerifier{n, v, nBytes, vBytes, t}
}

func parsePublicKey(publicKey *rsa.PublicKey) (n *big.Int, v *big.Int, nBytes int, vBytes int) {
	n, v = publicKey.N, big.NewInt(int64(publicKey.E))
	nLen := n.BitLen()
	vLen := v.BitLen() - 1 // note the -1; GQ1 only ever uses the (length of v) - 1, so we can just do this here rather than throughout
	nBytes = bytesForBits(nLen)
	vBytes = bytesForBits(vLen)
	return
}

func bytesForBits(bits int) int {
	return (bits + 7) / 8
}

func hash(byteCount int, data ...[]byte) ([]byte, error) {
	rng := sha3.NewShake256()
	for _, d := range data {
		rng.Write(d)
	}

	return randomBytes(rng, byteCount)
}

func randomBytes(rng io.Reader, byteCount int) ([]byte, error) {
	bytes := make([]byte, byteCount)

	_, err := io.ReadFull(rng, bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func parseJWT(jwt []byte) ([]byte, []byte, error) {
	headers, payload, signature, err := jws.SplitCompact(jwt)
	if err != nil {
		return nil, nil, err
	}

	// Signatures are over header and payload in the base64 url-encoded byte
	// form of `header + '.' + payload`
	signingPayload := append(headers, []byte(".")...)
	signingPayload = append(signingPayload, payload...)

	return signingPayload, signature, nil
}
