package set4

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"ramitmittal.com/cryptopals/internal/util"
	mysha "ramitmittal.com/cryptopals/internal/util/sha1"
)

func s4c25Edit(cipherText []byte, offset int, newText []byte) []byte {
	plainText := util.CtrEncrypt(cipherText, util.Some16ByteKey, util.Some8ByteNonce)

	editedText := append(plainText[0:offset], newText...)
	editedText = append(editedText, plainText[offset:]...)

	return util.CtrEncrypt(editedText, util.Some16ByteKey, util.Some8ByteNonce)
}

// Break "random access read/write" AES CTR
// https://cryptopals.com/sets/4/challenges/25
func S4c25() {
	plainText := util.ReadFile("./files/4-25.txt")

	util.Some16ByteKey = util.RandomBytes(16)
	util.Some8ByteNonce = bytes.Repeat([]byte{byte(0)}, 8)

	cipherText := util.CtrEncrypt(plainText, util.Some16ByteKey, util.Some8ByteNonce)
	editedCipherText := s4c25Edit(cipherText, 0, cipherText)
	fmt.Println(string(editedCipherText[0:len(plainText)]))
}

func s4c26func1(input string) []byte {
	prepend := "comment1=cooking%20MCs;userdata="
	append := ";comment2=%20like%20a%20pound%20of%20bacon"

	escapedInput := strings.ReplaceAll(input, ";", "\\;")
	escapedInput = strings.ReplaceAll(escapedInput, "=", "\\=")

	fullStr := prepend + escapedInput + append

	util.Some16ByteKey = util.RandomBytes(16)
	util.Some8ByteNonce = bytes.Repeat([]byte{byte(0)}, 8)

	return util.CtrEncrypt([]byte(fullStr), util.Some16ByteKey, util.Some8ByteNonce)
}

func s4c26func2(input []byte) bool {
	plainTextBytes := util.CtrEncrypt(input, util.Some16ByteKey, util.Some8ByteNonce)
	adminRegex := regexp.MustCompile(`[^\\];admin=true;`)
	return adminRegex.Match(plainTextBytes)
}

// CTR bitflipping
// https://cryptopals.com/sets/4/challenges/26
func S4c26() {

	encryptedText := s4c26func1("johnjohnjohnjohn;admi=true")

	// turn escape character \ before ; into anything else
	// turn escape character \ before = into n
	for i := 0; i < 255; i++ {
		for j := 0; j < 255; j++ {
			moddedEncr := encryptedText[:48]
			moddedEncr = append(moddedEncr, byte(i))
			moddedEncr = append(moddedEncr, encryptedText[49:54]...)
			moddedEncr = append(moddedEncr, byte(j))
			moddedEncr = append(moddedEncr, encryptedText[55:]...)

			isAdmin := s4c26func2(moddedEncr)
			if isAdmin {
				fmt.Printf("%d %d\n", i, j)
				// there will be multiple solutions
				return
			}
		}

	}
}

func s4c27func1(cipherText []byte) error {
	plainText := util.CbcDecrypt(cipherText, util.Some16ByteKey, util.Some16ByteKey)
	for _, b := range plainText {
		if b > 127 {
			return fmt.Errorf("high ascii value in: %s", plainText)
		}
	}
	return nil
}

// Recover the key from CBC with IV=Key
// https://cryptopals.com/sets/4/challenges/27
func S4c27() {
	util.Some16ByteKey = util.RandomBytes(16)

	plainText := `When I get older I will be stronger
They'll call me freedom just like a wavin' flag`

	var requiredPadding int
	if len(plainText)%16 == 0 {
		requiredPadding = 0
	} else {
		requiredPadding = 16 - (len(plainText) % 16)
	}
	paddedPlainText := util.Pkcs7pad([]byte(plainText), requiredPadding)

	cipherText := util.CbcEncrypt(paddedPlainText, util.Some16ByteKey, util.Some16ByteKey)

	modifiedCipherText := cipherText[:16]
	modifiedCipherText = append(modifiedCipherText, bytes.Repeat([]byte{byte(0)}, 16)...)
	modifiedCipherText = append(modifiedCipherText, cipherText[:16]...)

	err := s4c27func1(modifiedCipherText)
	recoveredPlainText := []byte(err.Error())[len("high ascii value in: "):]
	recoveredKey := util.XorStuff(recoveredPlainText[:16], recoveredPlainText[32:48])

	fmt.Printf("%d\n%d", util.Some16ByteKey, recoveredKey)
}

// Implement a SHA-1 keyed MAC
// https://cryptopals.com/sets/4/challenges/28
func S4c28() {
	{ // golang impl of sha1
		plainText := []byte("Hello, World!")
		hash := sha1.New()
		if _, err := hash.Write(plainText); err != nil {
			panic(err)
		}
		fmt.Printf("%x\n", hash.Sum(nil))
	}
	{ // our impl of sha1
		plainText := []byte("Hello, World!")
		hash := mysha.New()
		fmt.Printf("%x\n", hash.Sum(plainText))
	}

	{
		util.Some16ByteKey = util.RandomBytes(16)

		var hash1 []byte
		var hash2 []byte
		var hash3 []byte

		{
			plainText := []byte("Hello, World!")
			hash := sha1.New()
			if _, err := hash.Write(append(util.Some16ByteKey, plainText...)); err != nil {
				panic(err)
			}
			hash1 = hash.Sum(nil)
		}
		{
			plainText := []byte("Jello, World!")
			hash := sha1.New()
			if _, err := hash.Write(append(util.Some16ByteKey, plainText...)); err != nil {
				panic(err)
			}
			hash2 = hash.Sum(nil)
		}
		{
			plainText := []byte("Hello, World!")
			key := util.RandomBytes(16)
			hash := sha1.New()
			if _, err := hash.Write(append(key, plainText...)); err != nil {
				panic(err)
			}
			hash3 = hash.Sum(nil)
		}

		fmt.Printf("%x\n", hash1)
		fmt.Printf("%x\n", hash2)
		fmt.Printf("%x\n", hash3)
	}
}

func s4c29hash(plainText []byte) [20]byte {
	// this is the routine that generates the MAC

	if util.SomeRandomPrefix == nil {
		util.SomeRandomPrefix = util.RandomBytes(util.RandomInteger(50))
	}
	plainTextWithKey := append(util.SomeRandomPrefix, plainText...)

	hash := mysha.New()
	sum := hash.Sum(plainTextWithKey)
	return sum
}

func s4c29padding(originalLength int) []byte {
	// this is the routine that generates padding

	var padding []byte

	var tmp [64]byte
	tmp[0] = 0x80

	if originalLength%64 < 56 {
		padding = append(padding, tmp[0:56-originalLength%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-originalLength%64]...)
	}

	lengthInBits := originalLength << 3
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(lengthInBits))

	return append(padding, b...)
}

// Break a SHA-1 keyed MAC using length extension
// https://cryptopals.com/sets/4/challenges/29
func S4c29() {
	p1 := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	sumOfP1 := s4c29hash(p1)

	// We do not need to guess the length of the secret prefix
	// We need to guess the length of (secret || original-message || glue-padding), call this N
	// This will be a multiple of 64 (that's what the glue-padding does)

	// Let F = ";admin=true"
	// F will always lie on a block boundary
	// We length of message in padding for (secret || original-message || glue-padding || F) is N + len(F)
	// Let P3 = (F || 0x80 || <lots of zeros> || N + len(F))
	// The trick is to forge the length of the message in the padding
	// Make the SHA impl hash just the single P3 block without padding any more padding

	for i := 0; i < 10; i++ { // i is the guessed value of N / 64
		h1 := mysha.New()
		h1.LoadState(sumOfP1)

		p3 := []byte(";admin=true")
		requiredPadding := (i * 64) + len(p3)
		p3 = append(p3, s4c29padding(requiredPadding)...)

		h1.SumSingleBlockWithoutPadding(p3)
	}
}

// Break an MD4 keyed MAC using length extension
// https://cryptopals.com/sets/4/challenges/30
func S4c30() {
	// Too boring and I forgot how I tested c29, not doing this RN
}

func s4c31Func2(n time.Duration) {
	util.Some16ByteKey = util.RandomBytes(16)

	handler := func(w http.ResponseWriter, req *http.Request) {

		// for simplicity let's just assume that received hash will always be a valid hex string of length 20
		receivedHashHex := req.URL.Query().Get("signature")
		receivedHash, err := hex.DecodeString(receivedHashHex)
		if err != nil {
			panic(err)
		}

		var calculatedHash []byte

		if file, err := ioutil.ReadAll(req.Body); err != nil {
			panic(err)
		} else {
			hash := sha1.New()
			if _, err := hash.Write(append(util.Some16ByteKey, file...)); err != nil {
				panic(err)
			}
			calculatedHash = hash.Sum(nil)
		}

		for i := 0; i < 20; i++ {
			if receivedHash[i] != calculatedHash[i] {
				w.WriteHeader(500)
				return
			}

			<-time.After(n)
		}

		w.WriteHeader(200)
	}

	http.HandleFunc("/file", handler)
	if err := http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

// Implement and break HMAC-SHA1 with an artificial timing leak
// https://cryptopals.com/sets/4/challenges/31
func S4c31() {
	go s4c31Func2(50 * time.Millisecond)

	file := []byte("Hello, World!")
	var hmac [20]byte

	for i := 0; i < 20; i++ {
		for j := 0; j < 256; j++ {
			hmac[i] = byte(j)
			hmacStr := hex.EncodeToString(hmac[:])

			endpoint := "http://localhost:8090/file?signature=" + hmacStr
			startTime := time.Now()
			if _, err := http.Post(endpoint, "text/plain", bytes.NewReader(file)); err != nil {
				panic(err)
			}
			diff := time.Now().Sub(startTime)

			if diff > (time.Duration((i+1)*50) * time.Millisecond) {
				fmt.Printf(">>> %s\n", hmacStr)
				break
			}
		}
	}
}

// Break HMAC-SHA1 with a slightly less artificial timing leak
// https://cryptopals.com/sets/4/challenges/32
func S4c32() {
	duration := 5 * time.Millisecond
	go s4c31Func2(duration)

	file := []byte("Hello, World!")
	var hmac [20]byte

	for i := 0; i < 20; i++ {
		for j := 0; j < 256; j++ {
			hmac[i] = byte(j)
			hmacStr := hex.EncodeToString(hmac[:])

			endpoint := "http://localhost:8090/file?signature=" + hmacStr
			startTime := time.Now()
			if _, err := http.Post(endpoint, "text/plain", bytes.NewReader(file)); err != nil {
				panic(err)
			}
			diff := time.Now().Sub(startTime)

			minimumExpectedDifference := duration * time.Duration(i+1)

			// on printing the time diff, we learn that we gain several milliseconds over the minimum expected difference in each iteration
			// increase the expected difference by a factor larger than i with every iteration
			adjustedExpectedDifference := minimumExpectedDifference + time.Microsecond*time.Duration(i*200)
			if diff > (adjustedExpectedDifference) {
				// fmt.Printf("Time diff = %s\n", diff)
				// fmt.Println(hmac)
				break
			}

			// the increase itself won't solve the problem
			// add a backoff logic
			if j == 255 {
				i -= 2
			}
		}
	}

	fmt.Println(hmac)
}
