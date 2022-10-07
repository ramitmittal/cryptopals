package set6

import (
	"fmt"
	"math/big"

	"ramitmittal.com/cryptopals/internal/util"
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

// Bleichenbacher's e=3 RSA Attack
// https://cryptopals.com/sets/6/challenges/42
func S6c42() {
}
