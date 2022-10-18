package set6

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"ramitmittal.com/cryptopals/internal/util"
	"ramitmittal.com/cryptopals/internal/util/bignumbers"
	"ramitmittal.com/cryptopals/internal/util/dsa"
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

var (
	s6c43P *big.Int
	s6c43Q *big.Int
	s6c43G *big.Int
)

func s6c43Sign(m, x *big.Int) (r, s, k *big.Int) {
	fmt.Println("X ", x)

	qMinus1 := new(big.Int).Sub(s6c43Q, big.NewInt(1))
	zero := new(big.Int)
	for {
		k := util.RandomBigInt()
		if k.Cmp(zero) != 1 && k.Cmp(qMinus1) != -1 {
			continue
		}

		r = new(big.Int).Exp(s6c43G, k, s6c43P)
		r.Mod(r, s6c43Q)
		if r.Cmp(zero) == 0 {
			continue
		}

		s := new(big.Int).Mul(x, r)
		s.Add(s, m)
		s.Mod(s, s6c43Q)
		s.Mul(s, new(big.Int).ModInverse(k, s6c43Q))
		s.Mod(s, s6c43Q)
		if s.Cmp(zero) == 0 {
			continue
		}

		return r, s, k
	}
}

func s6c43Verify(m, r, s, y *big.Int) bool {
	zero := new(big.Int)
	if r.Cmp(zero) != 1 || s.Cmp(zero) != 1 {
		return false
	}
	if r.Cmp(s6c43Q) != -1 || s.Cmp(s6c43Q) != -1 {
		return false
	}

	w := new(big.Int).ModInverse(s, s6c43Q)

	u1 := new(big.Int).Mul(m, w)
	u1.Mod(u1, s6c43Q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, s6c43Q)

	v1 := new(big.Int).Exp(s6c43G, u1, s6c43P)
	v2 := new(big.Int).Exp(y, u2, s6c43P)
	v1.Mul(v1, v2)
	v1.Mod(v1, s6c43P)
	v1.Mod(v1, s6c43Q)

	return v1.Cmp(r) == 0
}

func s6c43AttackWithKnownK(m, r, s, k *big.Int) *big.Int {
	x := new(big.Int).Mul(s, k)
	x.Sub(x, m)
	x.Mul(x, new(big.Int).ModInverse(r, s6c43Q))
	x.Mod(x, s6c43Q)

	return x
}

func s6c43Challenge1() {
	x, y := dsa.DSAKeygen(s6c43P, s6c43Q, s6c43G)

	var m *big.Int
	{
		message := []byte("Hello, world!")
		h := sha1.New()
		if _, err := h.Write(message); err != nil {
			panic(err)
		}
		m = new(big.Int).SetBytes(h.Sum(nil))
	}

	r, s, k := s6c43Sign(m, x)

	recoveredX := s6c43AttackWithKnownK(m, r, s, k)
	fmt.Println("X ", recoveredX)

	fmt.Println(s6c43Verify(m, r, s, y))
}

func s643AttackWithSmallK(m, r, s, y *big.Int) {
	maxK := new(big.Int).Exp(big.NewInt(2), big.NewInt(16), nil)
	k := big.NewInt(-1)
	one := big.NewInt(1)

	rInv := new(big.Int).ModInverse(r, s6c43Q)

	for k.Cmp(maxK) < 0 {
		k.Add(k, one)

		kInv := new(big.Int).ModInverse(k, s6c43Q)
		if kInv == nil {
			continue
		}

		r1 := new(big.Int).Exp(s6c43G, k, s6c43P)
		r1.Mod(r1, s6c43Q)
		if r1.Cmp(r) != 0 {
			continue
		}

		x := new(big.Int).Mul(s, k)
		x.Sub(x, m)
		x.Mul(x, rInv)
		x.Mod(x, s6c43Q)

		{
			s1 := new(big.Int).Mul(x, r)
			s1.Add(s1, m)
			s1.Mod(s1, s6c43Q)
			s1.Mul(s1, kInv)
			s1.Mod(s1, s6c43Q)

			if s1.Cmp(s) == 0 {
				h := sha1.New()
				if _, err := h.Write([]byte(x.Text(16))); err != nil {
					panic(err)
				}
				fmt.Printf("%x\n", h.Sum(nil))
				break
			}
		}
	}
}

func s6c43Challenge2() {
	m := "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

	h := sha1.New()
	if _, err := h.Write([]byte(m)); err != nil {
		panic(err)
	}
	mh := h.Sum(nil)

	mhInt := new(big.Int)
	mhInt.SetBytes(mh)

	r := new(big.Int)
	r.SetString("548099063082341131477253921760299949438196259240", 10)

	s := new(big.Int)
	s.SetString("857042759984254168557880549501802188789837994940", 10)

	yStr := `84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
	abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
	e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
	1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
	bb283e6633451e535c45513b2d33c99ea17`
	yStr = strings.ReplaceAll(yStr, "\t", "")
	yStr = strings.ReplaceAll(yStr, "\n", "")
	y := new(big.Int)
	y.SetString(yStr, 16)

	s643AttackWithSmallK(mhInt, r, s, y)
}

// DSA key recovery from nonce
// https://cryptopals.com/sets/6/challenges/43
func S6c43() {
	s6c43P, s6c43Q, s6c43G = dsa.DSAParams()

	s6c43Challenge2()
}

type message struct {
	s *big.Int
	r *big.Int
	m *big.Int
}

func s6c44Read() []message {
	var messages []message

	if bytes, err := ioutil.ReadFile("files/6-44.txt"); err != nil {
		panic(err)
	} else {
		lines := strings.Split(string(bytes), "\n")

		for i := 0; i < len(lines)/4; i++ {
			sStr := lines[i*4+1]
			rStr := lines[i*4+2]
			mStr := lines[i*4+3]

			sStr = strings.TrimPrefix(sStr, "s: ")
			rStr = strings.TrimPrefix(rStr, "r: ")
			mStr = strings.TrimPrefix(mStr, "m: ")

			s := new(big.Int)
			s.SetString(sStr, 10)

			r := new(big.Int)
			r.SetString(rStr, 10)

			m := new(big.Int)
			m.SetString(mStr, 16)

			messages = append(messages, message{
				s: s,
				r: r,
				m: m,
			})
		}
	}

	return messages
}

// DSA nonce recovery from repeated nonce
// https://cryptopals.com/sets/6/challenges/44
func S6c44() {
	s6c43P, s6c43Q, s6c43G = dsa.DSAParams()

	yStr := `2d026f4bf30195ede3a088da85e398ef869611d0f68f07
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
    2971c3de5084cce04a2e147821`
	yStr = strings.ReplaceAll(yStr, "\t", "")
	yStr = strings.ReplaceAll(yStr, "\n", "")
	y := new(big.Int)
	y.SetString(yStr, 16)

	messages := s6c44Read()

	var messagesWithSameK [2]message

	rMap := make(map[string]int)
	for i, msg := range messages {
		if v, prs := rMap[msg.r.Text(10)]; prs {
			messagesWithSameK[0] = messages[v]
			messagesWithSameK[1] = messages[i]
			break
		}
		rMap[msg.r.Text(10)] = i
	}

	k := new(big.Int).Sub(messagesWithSameK[0].m, messagesWithSameK[1].m)
	s1 := new(big.Int).Sub(messagesWithSameK[0].s, messagesWithSameK[1].s)
	s1Inv := s1.ModInverse(s1, s6c43Q)
	k.Mul(k, s1Inv)
	k.Mod(k, s6c43Q)

	x := s6c43AttackWithKnownK(messagesWithSameK[0].m, messagesWithSameK[0].r, messagesWithSameK[0].s, k)
	h := sha1.New()
	if _, err := h.Write([]byte(x.Text(16))); err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", h.Sum(nil))
}

// Same as s6c43Sign except the zero comparisons
func s6c45Sign(m, x *big.Int) (r, s, k *big.Int) {
	fmt.Println("X ", x)

	qMinus1 := new(big.Int).Sub(s6c43Q, big.NewInt(1))
	zero := new(big.Int)
	for {
		k := util.RandomBigInt()
		if k.Cmp(zero) != 1 && k.Cmp(qMinus1) != -1 {
			continue
		}

		r = new(big.Int).Exp(s6c43G, k, s6c43P)
		r.Mod(r, s6c43Q)

		s := new(big.Int).Mul(x, r)
		s.Add(s, m)
		s.Mod(s, s6c43Q)
		s.Mul(s, new(big.Int).ModInverse(k, s6c43Q))
		s.Mod(s, s6c43Q)
		if s.Cmp(zero) == 0 {
			continue
		}

		return r, s, k
	}
}

// Same as s6c43Verify except the zero comparisons
func s6c45Verify(m, r, s, y *big.Int) bool {
	w := new(big.Int).ModInverse(s, s6c43Q)

	u1 := new(big.Int).Mul(m, w)
	u1.Mod(u1, s6c43Q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, s6c43Q)

	v1 := new(big.Int).Exp(s6c43G, u1, s6c43P)
	v2 := new(big.Int).Exp(y, u2, s6c43P)
	v1.Mul(v1, v2)
	v1.Mod(v1, s6c43P)
	v1.Mod(v1, s6c43Q)

	return v1.Cmp(r) == 0
}

// DSA parameter tampering
// https://cryptopals.com/sets/6/challenges/45
func S6c45() {
	s6c43P, s6c43Q, _ = dsa.DSAParams()
	s6c43G = new(big.Int)

	x, y := dsa.DSAKeygen(s6c43P, s6c43Q, s6c43G)

	{ // generate signature and verify it
		m := new(big.Int)
		m.SetBytes([]byte("bad bad"))

		r, s, _ := s6c45Sign(m, x)
		// r will be 0

		verified := s6c45Verify(m, r, s, y)
		fmt.Println("1: ", verified)
	}

	{ // generate any other signature for any other string
		m := new(big.Int)
		// skipped the SHA1 step
		m.SetBytes([]byte("bad bad"))

		r, s, _ := s6c45Sign(m, x)
		// r will be 0

		m1 := big.NewInt(42)
		verified := s6c45Verify(m1, r, s, y)
		fmt.Println("2: ", verified)
	}

	s6c43G.Add(s6c43P, big.NewInt(1))
	_, y = dsa.DSAKeygen(s6c43P, s6c43Q, s6c43G)

	// arbitrary value
	z := big.NewInt(78)
	zInv := new(big.Int).ModInverse(z, s6c43Q)

	r := new(big.Int).Exp(y, z, s6c43P)
	r.Mod(r, s6c43Q)

	s := new(big.Int).Mul(r, zInv)

	{
		m := new(big.Int)
		m.SetBytes([]byte("Hello, world"))

		verified := s6c43Verify(m, r, s, y)
		fmt.Println("3: ", verified)

		m.SetBytes([]byte("Goodbye, world"))

		verified = s6c43Verify(m, r, s, y)
		fmt.Println("4: ", verified)
	}
}
