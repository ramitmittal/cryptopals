package set5

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"ramitmittal.com/cryptopals/internal/util"
	"ramitmittal.com/cryptopals/internal/util/bignumbers"
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

func s5c35A(chanA <-chan exchange, chanB chan<- exchange) {
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
		numbers: []big.Int{*p, *g},
	}
	<-chanA
	chanB <- exchange{
		stage:   2,
		numbers: []big.Int{*a1},
	}
	ex3 := <-chanA
	b1 := ex3.numbers[0]

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
		stage: 4,
		text:  message1,
	}
}

func s5c35Matk0(chanA, chanB chan<- exchange, chanM <-chan exchange) {
	ex0 := <-chanM

	p := ex0.numbers[0]
	g := big.Int{}
	g.SetInt64(1)
	// B calculates b1 = 1
	// b1 = (g ** b) mod p
	// b1 = (1 ** anything) mod largeNumber = 1
	chanB <- exchange{
		stage:   ex0.stage,
		numbers: []big.Int{p, g},
	}

	// Forward empty ACK message
	ex1 := <-chanM
	chanA <- ex1

	// for A
	// s = (b1 ** a) mod p
	// s = (1 ** anything) mod largeNumber = 1
	// for B
	// s = (a1 ** b) mod p
	// send a1 = 1 to B
	ex2 := <-chanM
	chanB <- exchange{
		stage:   ex2.stage,
		numbers: []big.Int{g},
	}

	ex3 := <-chanM
	chanA <- ex3

	ex4 := <-chanM
	receivedMessage := ex4.text

	h := sha1.New()
	if _, err := h.Write([]byte{1}); err != nil {
		panic(err)
	}
	key := h.Sum(nil)[0:16]
	iv := receivedMessage[len(receivedMessage)-16:]
	receivedPlain := util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
	fmt.Printf("M recevied: %s\n", receivedPlain)

	chanB <- ex4
}

func s5c35Matk1(chanA, chanB chan<- exchange, chanM <-chan exchange) {
	ex0 := <-chanM

	p := ex0.numbers[0]
	// B calculates b1 = 0
	// b1 = (g ** b) mod p
	// b1 = (p ** anything) mod p = 0
	chanB <- exchange{
		stage:   ex0.stage,
		numbers: []big.Int{p, p},
	}

	// Forward empty ACK message
	ex1 := <-chanM
	chanA <- ex1

	ex2 := <-chanM
	// for B
	// s = (a1 ** b) mod p
	// send a1 = p to B
	chanB <- exchange{
		stage:   ex2.stage,
		numbers: []big.Int{p},
	}

	ex3 := <-chanM
	chanA <- ex3

	ex4 := <-chanM
	receivedMessage := ex4.text

	s := big.Int{}
	s.SetInt64(0)

	h := sha1.New()
	if _, err := h.Write(s.Bytes()); err != nil {
		panic(err)
	}
	key := h.Sum(nil)[0:16]
	iv := receivedMessage[len(receivedMessage)-16:]
	receivedPlain := util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
	fmt.Printf("M recevied: %s\n", receivedPlain)

	chanB <- ex4
}

func s5c35Matk2(chanA, chanB chan<- exchange, chanM <-chan exchange) {
	ex0 := <-chanM

	one := big.Int{}
	one.SetInt64(1)
	p := ex0.numbers[0]
	g := big.Int{}
	g.Sub(&p, &one)

	// b1 == 1 || b1 == p-1
	chanB <- exchange{
		stage:   ex0.stage,
		numbers: []big.Int{p, g},
	}

	// Forward empty ACK message
	ex1 := <-chanM
	chanA <- ex1

	ex2 := <-chanM
	// for B
	// s == b1
	chanB <- exchange{
		stage:   ex2.stage,
		numbers: []big.Int{g},
	}

	ex3 := <-chanM
	// value of s may be different for A and B
	// we need to reencrypt all messages
	b1 := ex3.numbers[0]
	chanA <- ex3

	ex4 := <-chanM
	receivedMessage := ex4.text

	var sForA *big.Int
	var receivedPlain []byte
	{
		s := big.Int{}
		s.SetInt64(1)

		h := sha1.New()
		if _, err := h.Write(s.Bytes()); err != nil {
			panic(err)
		}
		key := h.Sum(nil)[0:16]
		iv := receivedMessage[len(receivedMessage)-16:]
		receivedPlain = util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
		if strings.HasPrefix(string(receivedPlain), "TT") {
			fmt.Println("M recevied: ", string(receivedPlain))
			sForA = &s
		}
	}
	if sForA == nil {
		h := sha1.New()
		if _, err := h.Write(g.Bytes()); err != nil {
			panic(err)
		}
		key := h.Sum(nil)[0:16]
		iv := receivedMessage[len(receivedMessage)-16:]
		receivedPlain = util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
		if strings.HasPrefix(string(receivedPlain), "TT") {
			fmt.Println("M recevied: ", string(receivedPlain))
			sForA = &g
		}
	}
	if sForA == nil {
		panic(errors.New("cannot decrypt message from A"))
	}

	{
		// re-encrypt for B
		h := sha1.New()
		if _, err := h.Write(b1.Bytes()); err != nil {
			panic(err)
		}
		key := h.Sum(nil)[0:16]
		iv := util.RandomBytes(16)
		message1 := util.CbcEncrypt(receivedPlain, key, iv)
		message1 = append(message1, iv...)
		chanB <- exchange{
			stage: 4,
			text:  message1,
		}
	}
}

func s5c35B(chanA chan<- exchange, chanB <-chan exchange) {
	ex0 := <-chanB

	p := ex0.numbers[0]
	g := ex0.numbers[1]
	maxInt := int64(^uint(0) >> 1)
	b := util.RandomBigInt(maxInt)
	b1 := &big.Int{}
	b1 = b1.Exp(&g, b, &p)

	chanA <- exchange{
		stage: 1,
	}
	ex2 := <-chanB
	a1 := ex2.numbers[0]
	chanA <- exchange{
		stage:   3,
		numbers: []big.Int{*b1},
	}

	ex4 := <-chanB
	receivedMessage := ex4.text
	s := &big.Int{}
	s = s.Exp(&a1, b, &p)
	h := sha1.New()
	if _, err := h.Write(s.Bytes()); err != nil {
		panic(err)
	}
	key := h.Sum(nil)[0:16]

	iv := receivedMessage[len(receivedMessage)-16:]
	receivedPlain := util.CbcDecrypt(receivedMessage[:len(receivedMessage)-16], key, iv)
	fmt.Printf("B recevied: %s\n", receivedPlain)
}

func s5c35func1() {
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

// Implement DH with negotiated groups, and break with malicious "g" parameters
// https://cryptopals.com/sets/5/challenges/35
func S5c35() {
	var wg sync.WaitGroup
	wg.Add(3)

	chanA := make(chan exchange, 0)
	chanM := make(chan exchange, 0)
	chanB := make(chan exchange, 0)

	// A
	go func() {
		s5c35A(chanA, chanM)
		wg.Done()
	}()

	// M
	go func() {
		s5c35Matk2(chanA, chanB, chanM)
		wg.Done()
	}()

	// B
	go func() {
		s5c35B(chanM, chanB)
		wg.Done()
	}()

	wg.Wait()
}

func s5c36Client(chanC, chanS chan exchange) {
	maxInt := int64(^uint(0) >> 1)

	n := bignumbers.NistPrime()
	g := big.NewInt(2)
	k := big.NewInt(3)
	i := []byte("pillow@example.com")
	password := []byte("bb065f841eb339a6cef96eb6")

	a := util.RandomBigInt(maxInt)
	a1 := &big.Int{}
	a1.Exp(g, a, n)

	chanS <- exchange{
		stage:   0,
		numbers: []big.Int{*a1},
		text:    i,
	}

	ex1 := <-chanC

	u := &big.Int{}
	{
		a1b1 := append(a1.Bytes(), ex1.numbers[0].Bytes()...)
		h := sha256.New()
		if _, err := h.Write(a1b1); err != nil {
			panic(err)
		}

		uh := h.Sum(nil)
		u.SetBytes(uh)
	}

	x := &big.Int{}
	{
		saltAndPassword := append(ex1.numbers[1].Bytes(), []byte(password)...)
		h := sha256.New()
		if _, err := h.Write(saltAndPassword); err != nil {
			panic(err)
		}
		xh := h.Sum(nil)
		x.SetBytes(xh)
	}
	s := &big.Int{}
	var k1 []byte
	{
		b1 := ex1.numbers[0]
		o1 := &big.Int{}
		o1.Exp(g, x, n)

		o1.Mul(k, o1)
		o1.Sub(&b1, o1)

		o2 := &big.Int{}
		o2.Mul(u, x)
		o2.Add(a, o2)
		s.Exp(o1, o2, n)

		h := sha256.New()
		if _, err := h.Write(s.Bytes()); err != nil {
			panic(err)
		}
		k1 = h.Sum(nil)
	}

	ex2 := <-chanC

	var eh []byte
	{
		k1salt := append(k1, ex1.numbers[1].Bytes()...)
		h := sha256.New()
		if _, err := h.Write(k1salt); err != nil {
			panic(err)
		}
		eh = h.Sum(nil)
	}

	fmt.Println(ex2.text)
	fmt.Println(eh)
}

func s5c36Server(chanC, chanS chan exchange) {
	maxInt := int64(^uint(0) >> 1)

	n := bignumbers.NistPrime()
	g := big.NewInt(2)
	k := big.NewInt(3)
	password := []byte("bb065f841eb339a6cef96eb6")
	salt := util.RandomBigInt(maxInt)

	v := &big.Int{}
	{
		saltAndPassword := append(salt.Bytes(), password...)
		h := sha256.New()
		if _, err := h.Write(saltAndPassword); err != nil {
			panic(err)
		}
		xh := h.Sum(nil)
		x := &big.Int{}
		x.SetBytes(xh)

		v.Exp(g, x, n)
	}

	ex0 := <-chanS

	b := util.RandomBigInt(maxInt)
	b1 := &big.Int{}
	{
		one := &big.Int{}
		one.Mul(k, v)
		two := &big.Int{}
		two.Exp(g, b, n)
		b1.Add(one, two)
	}

	chanC <- exchange{
		stage:   1,
		numbers: []big.Int{*b1, *salt},
	}

	u := &big.Int{}
	{
		a1b1 := append(ex0.numbers[0].Bytes(), b1.Bytes()...)
		h := sha256.New()
		if _, err := h.Write(a1b1); err != nil {
			panic(err)
		}
		uh := h.Sum(nil)
		u.SetBytes(uh)
	}

	s := &big.Int{}
	var k1 []byte
	{
		a1 := ex0.numbers[0]
		o1 := &big.Int{}

		o1.Exp(v, u, n)

		o1.Mul(&a1, o1)
		s.Exp(o1, b, n)
		h := sha256.New()
		if _, err := h.Write(s.Bytes()); err != nil {
			panic(err)
		}
		k1 = h.Sum(nil)
	}

	var eh []byte
	{
		k1salt := append(k1, salt.Bytes()...)
		h := sha256.New()
		if _, err := h.Write(k1salt); err != nil {
			panic(err)
		}
		eh = h.Sum(nil)
	}

	chanC <- exchange{
		stage: 2,
		text:  eh,
	}
}

// Implement Secure Remote Password (SRP)
// https://cryptopals.com/sets/5/challenges/36
func S5c36() {
	var wg sync.WaitGroup
	wg.Add(2)

	chanS := make(chan exchange)
	chanC := make(chan exchange)

	// C
	go func() {
		s5c36Client(chanC, chanS)
		wg.Done()
	}()

	// S
	go func() {
		s5c36Server(chanC, chanS)
		wg.Done()
	}()

	wg.Wait()
}
