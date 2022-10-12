package set6

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"math/big"

	"ramitmittal.com/cryptopals/internal/util"
	"ramitmittal.com/cryptopals/internal/util/bignumbers"
	"ramitmittal.com/cryptopals/internal/util/rsa"
)

type exchange struct {
	stage   int
	numbers []big.Int
}

func s6c41Server(chanChan chan exchange) {
	e, n, d := rsa.Keygen()

	chanChan <- exchange{
		stage:   0,
		numbers: []big.Int{*e, *n},
	}

	p := big.NewInt(42)
	fmt.Println("Server: original plain text: ", p)

	c := new(big.Int).Exp(p, e, n)
	chanChan <- exchange{
		stage:   1,
		numbers: []big.Int{*c},
	}

	ex2 := <-chanChan

	p1 := new(big.Int).Exp(&ex2.numbers[0], d, n)
	chanChan <- exchange{
		stage:   3,
		numbers: []big.Int{*p1},
	}
}

// Implement unpadded message recovery oracle
// https://cryptopals.com/sets/6/challenges/41
func S6c41() {
	chanChan := make(chan exchange)

	go s6c41Server(chanChan)

	ex0 := <-chanChan
	e := &ex0.numbers[0]
	n := &ex0.numbers[1]

	ex1 := <-chanChan
	c := &ex1.numbers[0]

	s := util.RandomBigInt()
	s.Mod(s, n)

	c1 := new(big.Int).Exp(s, e, n)
	c1.Mul(c1, c)
	c1.Mod(c1, n)

	chanChan <- exchange{
		stage:   2,
		numbers: []big.Int{*c1},
	}

	ex3 := <-chanChan

	p, _ := new(big.Int).DivMod(&ex3.numbers[0], s, n)

	fmt.Println("Attacker: recovered plain text: ", p)
}

var (
	s6c42E *big.Int
	s6c42N *big.Int
	s6c42D *big.Int
)

func s6c42Verify(msg, receivedSignature []byte) bool {
	rsNumber := new(big.Int).SetBytes(receivedSignature)
	rsNumber.Exp(rsNumber, s6c42E, s6c42N)

	rsBytes := rsNumber.Bytes()[2:]

	paddingCount := 0
	for ; paddingCount < len(rsBytes); paddingCount++ {
		if rsBytes[paddingCount] != byte(255) {
			break
		}
	}
	rsBytes = rsBytes[paddingCount+16:]

	h := sha1.New()
	if _, err := h.Write(msg); err != nil {
		panic(err)
	}
	calculatedHash := h.Sum(nil)

	for i := 0; i < 20; i++ {
		if rsBytes[i] != calculatedHash[i] {
			return false
		}
	}

	return true
}

// Bleichenbacher's e=3 RSA Attack
// https://cryptopals.com/sets/6/challenges/42
func S6c42() {
	keyLengthBytes := 1024 / 8
	s6c42E, s6c42N, s6c42D = rsa.Keygen()

	dummyASN1 := bytes.Repeat([]byte{byte(7)}, 15)

	// plain text message
	m1 := []byte("hi mom")
	var hash1 []byte
	{
		h := sha1.New()
		if _, err := h.Write(m1); err != nil {
			panic(err)
		}
		hash1 = h.Sum(nil)
	}

	// a valid signature generated with the private key
	var s1 *big.Int
	{
		paddingBytes := keyLengthBytes - len(hash1) - len(dummyASN1) - 3
		signature1 := []byte{byte(0), byte(1)}
		signature1 = append(signature1, bytes.Repeat([]byte{byte(255)}, paddingBytes)...)
		signature1 = append(signature1, byte(0))
		signature1 = append(signature1, dummyASN1...)
		signature1 = append(signature1, hash1...)

		s1 = new(big.Int).SetBytes(signature1)
		s1.Exp(s1, s6c42D, s6c42N)
	}

	// invalid forged signature
	var s2 *big.Int
	{
		signature2 := []byte{byte(0), byte(1), byte(255), byte(0)}
		signature2 = append(signature2, dummyASN1...)
		signature2 = append(signature2, hash1...)

		garbage := bytes.Repeat([]byte{byte(0)}, keyLengthBytes-len(signature2))
		signature2 = append(signature2, garbage...)
		s2x := new(big.Int).SetBytes(signature2)

		// s2 is the cube root of the closest perfect cube less than s2x
		s2 = bignumbers.CubeRoot(s2x)
	}

	// a forged perfect cube
	var s3 *big.Int
	{
		sx := new(big.Int).Add(s2, big.NewInt(1))

		// s6c42E is 3
		sx = sx.Exp(sx, s6c42E, nil)

		signature3 := []byte{byte(0), byte(1), byte(255), byte(0)}
		signature3 = append(signature3, dummyASN1...)
		signature3 = append(signature3, hash1...)

		garbage := bytes.Repeat([]byte{byte(0)}, keyLengthBytes-len(signature3))

		// signature4 is same as signature2
		signature4 := append(signature3, garbage...)
		signature4Number := new(big.Int).SetBytes(signature4)

		difference := new(big.Int).Sub(sx, signature4Number)
		garbage = bytes.Repeat([]byte{byte(0)}, keyLengthBytes-len(signature3)-len(difference.Bytes()))
		signature4 = append(signature3, garbage...)
		signature4 = append(signature4, difference.Bytes()...)
		s3x := new(big.Int).SetBytes(signature4)
		s3 = bignumbers.CubeRoot(s3x)
	}

	fmt.Println(s6c42Verify(m1, s3.Bytes()))
}

// DSA key recovery from nonce
// https://cryptopals.com/sets/6/challenges/43
func S6c43() {

}
