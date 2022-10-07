package rsa

import (
	"crypto/rand"
	"math/big"

	"ramitmittal.com/cryptopals/internal/util/bignumbers"
)

func Keygen() (e, n, d *big.Int) {
	one := big.NewInt(1)
	e = big.NewInt(3)

	for {
		p, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			panic(err)
		}
		q, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			panic(err)
		}

		if p.Cmp(q) == 0 {
			continue
		}

		n = new(big.Int).Mul(p, q)

		et1 := new(big.Int).Sub(p, one)
		et2 := new(big.Int).Sub(q, one)
		et := bignumbers.LCM(et1, et2)

		d = new(big.Int).ModInverse(e, et)

		if d != nil {
			break
		}
	}

	return e, n, d
}
