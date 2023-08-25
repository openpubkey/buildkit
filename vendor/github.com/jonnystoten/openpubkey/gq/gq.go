package gq

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

var prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

type Proof []SingleProof

func (p Proof) Ys() []*big.Int {
	Ys := make([]*big.Int, len(p))
	for i, sp := range p {
		Ys[i] = sp.Y
	}
	return Ys
}

func (p Proof) Validate() bool {
	for _, sp := range p {
		if sp.Y.Cmp(big.NewInt(1)) < 0 || sp.Z.Cmp(big.NewInt(1)) < 0 {
			return false
		}
	}
	return true
}

func (p Proof) Verify(signingPayload []byte, publicKey *rsa.PublicKey) bool {
	N, e := publicKey.N, publicKey.E
	encodedMessage := encodePKCS1v15(publicKey.Size(), signingPayload)
	X := new(big.Int).SetBytes(encodedMessage)

	Ys := p.Ys()
	challenges := generateChallenges(e, N, X, Ys)

	for i, proof := range p {
		Y := proof.Y
		Z := proof.Z
		c := challenges[i]
		rhs := new(big.Int).Exp(X, c, N)
		rhs.Mul(rhs, Y)
		rhs.Mod(rhs, N)

		lhs := new(big.Int).Exp(Z, big.NewInt(int64(e)), N)

		if lhs.Cmp(rhs) != 0 {
			return false
		}
	}
	return true
}

func (p Proof) Encode() string {
	var bin []byte
	bin = append(bin, byte(len(p)))

	for _, proof := range p {
		bin = append(bin, proof.Y.Bytes()...)
		bin = append(bin, proof.Z.Bytes()...)
	}

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(bin)))
	base64.StdEncoding.Encode(encoded, bin)

	return string(encoded)
}

func DecodeProof(s string) (*Proof, error) {
	var proof Proof

	bin, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	length, bin := bin[0], bin[1:]

	for i := 0; i < int(length); i++ {
		start := i * 512
		var single SingleProof
		y, z := bin[start:start+256], bin[start+256:start+512]
		single.Y = new(big.Int).SetBytes(y)
		single.Z = new(big.Int).SetBytes(z)
		proof = append(proof, single)
	}

	return &proof, nil
}

func Prove(signingPayload []byte, signature []byte, publicKey *rsa.PublicKey, bits int) Proof {
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, s256(signingPayload), signature)
	if err != nil {
		panic(err)
	}

	N, e := publicKey.N, publicKey.E
	encodedMessage := encodePKCS1v15(publicKey.Size(), signingPayload)
	X := new(big.Int).SetBytes(encodedMessage)
	x := new(big.Int).SetBytes(signature)
	// x := new(big.Int).SetBytes([]byte("not the sig"))

	count := bits / int(math.Log2(float64(e)))
	if count < 1 {
		panic("less than one iteration")
	}
	// fmt.Printf("count: %v\n", count)

	ys := gqGenerateRandomLittleYs(count, N)
	Ys := gqGenerateYs(ys, N, e)
	challenges := generateChallenges(e, N, X, Ys)

	var proof Proof
	for i, y := range ys {
		Y := Ys[i]
		c := challenges[i]
		Z := new(big.Int).Exp(x, c, N)
		Z.Mul(Z, y)
		Z.Mod(Z, N)

		p := SingleProof{Y, Z}
		// fmt.Printf("made a proof with Y: %v\n", p.Y)
		proof = append(proof, p)
	}
	return proof
}

type SingleProof struct {
	Y *big.Int
	Z *big.Int
}

func (p *SingleProof) Encode() string {
	encodedY := make([]byte, base64.RawURLEncoding.EncodedLen(len(p.Y.Bytes())))
	base64.RawURLEncoding.Encode(encodedY, p.Y.Bytes())
	encodedZ := make([]byte, base64.RawURLEncoding.EncodedLen(len(p.Z.Bytes())))
	base64.RawURLEncoding.Encode(encodedZ, p.Z.Bytes())
	return fmt.Sprintf("%v.%v", string(encodedY), string(encodedZ))
}

func DecodeSingle(s string) (*SingleProof, error) {
	parts := strings.SplitN(s, ".", 2)
	YBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	Y := new(big.Int).SetBytes(YBytes)
	ZBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	Z := new(big.Int).SetBytes(ZBytes)

	return &SingleProof{Y, Z}, nil
}

func randomBigInt(rng io.Reader, min, max *big.Int) *big.Int {
	y, err := rand.Int(rng, new(big.Int).Sub(max, min))
	if err != nil {
		panic(err)
	}
	return y.Add(y, min)
}

func gqGenerateRandomLittleYs(count int, N *big.Int) []*big.Int {
	one := big.NewInt(1)

	ys := make([]*big.Int, count)

	for i := 0; i < count; i++ {
		// fmt.Println("proving that we know the signature without revealing it")
		// fmt.Printf("signature as an int x = %v\n", x)

		// round 1

		// fmt.Println("finding a random number y from Z_N^* (integers between 1 and n-1 coprime to n)")
		// y <-$ Z_N^*
		var y *big.Int
		for {
			// Sample from Z_N^*
			y = randomBigInt(rand.Reader, one, N)
			// fmt.Printf("trying %v\n", y)
			if new(big.Int).GCD(nil, nil, y, N).Cmp(one) == 0 {
				// fmt.Println("looks good")
				break
			}
		}
		// fmt.Printf("y = %v\n", y)
		ys[i] = y
	}

	return ys
}

func gqGenerateYs(ys []*big.Int, N *big.Int, e int) []*big.Int {
	Ys := make([]*big.Int, len(ys))

	for i, y := range ys {
		// fmt.Println("calculating Y <- y^e mod n (basically rsa encrypting y with the public key)")
		// Y <- y^e mod n
		// (rsa encrypt y)
		Y := new(big.Int).Exp(y, big.NewInt(int64(e)), N)
		Ys[i] = Y
	}

	return Ys
}

// if all challenges are zero, a fake signature can be created.
// this can happen by random chance based on the value of each Y.
// if there are enough Ys as input, the chance of this happening becomes
// incredibly small. With 16 Ys the total size of the challenges is 256 bits
// so to brute-force this is basically the same as brute-forcing a single
// SHA256, i.e. not possible.
//
// However, it does beg the question, why not just disallow zero as a possible value?
func generateChallenges(e int, N, X *big.Int, Ys []*big.Int) []*big.Int {
	challenges := make([]*big.Int, len(Ys))

	rng := sha3.NewShake256()
	rng.Write(N.Bytes())
	rng.Write(X.Bytes())
	rng.Write(big.NewInt(int64(e)).Bytes())
	for _, Y := range Ys {
		rng.Write(Y.Bytes())
	}

	for i := range Ys {
		c, err := rand.Int(rng, big.NewInt(int64(e)))
		if err != nil {
			panic(err)
		}
		challenges[i] = c
	}

	return challenges
}

func generateChallengeSingle(e int, N, Y, X, prevY *big.Int) *big.Int {
	rng := sha3.NewShake256()
	rng.Write([]byte(fmt.Sprintf("d:%v:%v:%v:%v:%v", e, N, Y, X, prevY)))
	c, _ := rand.Int(rng, big.NewInt(int64(e)))
	return c
}

func generateBiggerChallenge(e int, N, Y, X *big.Int) *big.Int {
	hash := make([]byte, 1024)
	sha3.ShakeSum256(hash, []byte(fmt.Sprintf("d:%v:%v:%v:%v", e, N, Y, X)))
	return new(big.Int).SetBytes(hash)
}

func encodePKCS1v15(k int, data []byte) []byte {
	hashLen := crypto.SHA256.Size()
	tLen := len(prefix) + hashLen

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)

	hashed := sha256.Sum256(data)
	copy(em[k-hashLen:k], hashed[:])
	return em
}

func s256(d []byte) []byte {
	h := sha256.Sum256(d)
	return h[:]
}

func ecdsa_sha256(d []byte, pk *ecdsa.PrivateKey, rng io.Reader) []byte {
	hash := s256(d)
	sig, err := ecdsa.SignASN1(rand.Reader, pk, hash)
	if err != nil {
		panic(err)
	}
	return sig
}
