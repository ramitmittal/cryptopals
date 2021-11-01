package set5

import (
	"fmt"
	"math/big"
	"strings"

	"ramitmittal.com/cryptopals/internal/util"
)

// Implement Diffie-Hellman
// https://cryptopals.com/sets/5/challenges/33
func S5c33() {
	// https://stackoverflow.com/questions/6878590/the-maximum-value-for-an-int-type-in-go
	maxInt := int64(^uint(0) >> 1)

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

	p := &big.Int{}
	p.SetString(pStr, 16)

	g := &big.Int{}
	g.SetInt64(2)

	a := util.RandomBigInt(maxInt)
	a1 := &big.Int{}
	a1 = a1.Exp(g, a, p)

	b := util.RandomBigInt(maxInt)
	b1 := &big.Int{}
	b1 = b1.Exp(g, b, p)

	s := &big.Int{}
	s = s.Exp(b1, a, p)

	s1 := &big.Int{}
	s1 = s1.Exp(a1, b, p)

	fmt.Println(s.String())
	fmt.Println(s1.String())
}
