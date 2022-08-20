package set5

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"math/big"
	"strings"
	"sync"

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

type exchange struct {
	stage   int
	numbers []big.Int
	text    []byte
}

func s5c34A(chanA <-chan exchange, chanB chan<- exchange) {
	p := &big.Int{}
	g := &big.Int{}
	a := &big.Int{}
	a1 := &big.Int{}

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

	p.SetString(pStr, 16)
	g.SetInt64(2)

	a = util.RandomBigInt(maxInt)
	a1 = a1.Exp(g, a, p)

	chanB <- exchange{
		stage:   0,
		numbers: []big.Int{*p, *g, *a1},
	}

	ex1 := <-chanA
	b1 := ex1.numbers[0]

	s := &big.Int{}
	s = s.Exp(&b1, a, p)

	h := sha1.New()
	if _, err := h.Write(s.Bytes()); err != nil {
		panic(err)
	}
	key := h.Sum(nil)[0:16]

	iv := util.RandomBytes(16)
	message1 := util.CbcEncrypt(bytes.Repeat([]byte("T"), 16), key, iv)
	message1 = append(message1, iv...)
	chanB <- exchange{
		stage: 2,
		text:  message1,
	}

	ex3 := <-chanA
	receivedMessage := ex3.text
	iv = receivedMessage[len(receivedMessage)-16:]
	receivedPlain := util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
	fmt.Printf("A recevied: %s\n", receivedPlain)
}

func s5c34M(chanA, chanB chan<- exchange, chanM <-chan exchange) {
	ex0 := <-chanM

	p := ex0.numbers[0]
	g := ex0.numbers[1]
	a1 := ex0.numbers[2]
	_ = a1

	chanB <- exchange{
		stage:   0,
		numbers: []big.Int{p, g, p},
	}

	ex1 := <-chanM
	b1 := ex1.numbers[0]
	_ = b1

	chanA <- exchange{
		stage:   1,
		numbers: []big.Int{p},
	}

	ex2 := <-chanM
	{
		receivedMessage := ex2.text

		// s = (p ** b) mod p
		// s = (p ** a) mod p
		// s is 0

		h := sha1.New()
		if _, err := h.Write([]byte{}); err != nil {
			panic(err)
		}
		key := h.Sum(nil)[0:16]
		iv := receivedMessage[len(receivedMessage)-16:]
		receivedPlain := util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
		fmt.Printf("M recevied: %s\n", receivedPlain)
	}

	chanB <- ex2

	ex3 := <-chanM
	chanA <- ex3
}

func s5c34B(chanA chan<- exchange, chanB <-chan exchange) {
	ex0 := <-chanB

	p := ex0.numbers[0]
	g := ex0.numbers[1]
	a1 := ex0.numbers[2]

	maxInt := int64(^uint(0) >> 1)

	b := util.RandomBigInt(maxInt)
	b1 := &big.Int{}
	b1 = b1.Exp(&g, b, &p)

	s := &big.Int{}
	s = s.Exp(&a1, b, &p)

	chanA <- exchange{
		stage:   1,
		numbers: []big.Int{*b1},
	}

	ex2 := <-chanB
	receivedMessage := ex2.text

	h := sha1.New()
	if _, err := h.Write(s.Bytes()); err != nil {
		panic(err)
	}
	key := h.Sum(nil)[0:16]

	iv := receivedMessage[len(receivedMessage)-16:]
	receivedPlain := util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
	fmt.Printf("B recevied: %s\n", receivedPlain)

	iv = util.RandomBytes(16)
	message2 := util.CbcEncrypt(receivedPlain, key, iv)
	message2 = append(message2, iv...)
	chanA <- exchange{
		stage: 3,
		text:  message2,
	}
}

func s5c34func1() {
	// This is the version without MITM

	var wg sync.WaitGroup
	wg.Add(2)

	// the channel A reads from
	chanA := make(chan exchange, 0)
	// the channel B reads from
	chanB := make(chan exchange, 0)

	// A
	go func() {
		s5c34A(chanA, chanB)
		wg.Done()
	}()

	// B
	go func() {
		s5c34B(chanA, chanB)
		wg.Done()
	}()

	wg.Wait()
}

// Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
// https://cryptopals.com/sets/5/challenges/34
func S5c34() {
	var wg sync.WaitGroup
	wg.Add(3)

	chanA := make(chan exchange, 0)
	chanM := make(chan exchange, 0)
	chanB := make(chan exchange, 0)

	// A
	go func() {
		s5c34A(chanA, chanM)
		wg.Done()
	}()

	// M
	go func() {
		s5c34M(chanA, chanB, chanM)
		wg.Done()
	}()

	// B
	go func() {
		s5c34B(chanM, chanB)
		wg.Done()
	}()

	wg.Wait()
}
