package util

import (
	"crypto/rand"
	"math/big"
)

func RandomInteger(max int64) int64 {
	if nBig, err := rand.Int(rand.Reader, big.NewInt(max)); err != nil {
		panic(err)
	} else {
		return nBig.Int64()
	}
}

func RandomBigInt(max int64) *big.Int {
	if nBig, err := rand.Int(rand.Reader, big.NewInt(max)); err != nil {
		panic(err)
	} else {
		return nBig
	}
}

func RandomBytes(n int64) []byte {
	randomBytes := make([]byte, n)

	if _, err := rand.Read(randomBytes); err != nil {
		panic(err)
	}

	return randomBytes
}
