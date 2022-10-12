package bignumbers

import (
	"math/big"
	"strings"
)

func NistPrime() *big.Int {
	p := &big.Int{}

	pStr := `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
	e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
	3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
	6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
	24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
	c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
	bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
	fffffffffffff`
	pStr = strings.ReplaceAll(pStr, "\t", "")
	pStr = strings.ReplaceAll(pStr, "\n", "")
	p.SetString(pStr, 16)

	return p
}

// Returns rounded down integer for non-perfect cubes
func CubeRoot(cube *big.Int) *big.Int {
	big1 := big.NewInt(1)
	big3 := big.NewInt(3)

	x := new(big.Int).Rsh(cube, uint(cube.BitLen())/3*2)
	if x.Sign() == 0 {
		return nil
	}
	for {
		d := new(big.Int).Exp(x, big3, nil)
		d.Sub(d, cube)
		d.Div(d, big3)
		d.Div(d, x)
		d.Div(d, x)
		if d.Sign() == 0 {
			break
		}
		x.Sub(x, d)
	}
	for new(big.Int).Exp(x, big3, nil).Cmp(cube) < 0 {
		x.Add(x, big1)
	}
	for new(big.Int).Exp(x, big3, nil).Cmp(cube) > 0 {
		x.Sub(x, big1)
	}
	return x
}

func LCM(a, b *big.Int) *big.Int {
	x := new(big.Int).Mul(a, b)
	y := new(big.Int).GCD(nil, nil, a, b)

	return new(big.Int).Div(x, y)
}
