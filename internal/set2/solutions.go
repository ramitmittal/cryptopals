package set2

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"ramitmittal.com/cryptopals/internal/util"
)

// Implement PKCS#7 padding
// https://cryptopals.com/sets/2/challenges/9
func S2c9() {
	input := []byte("YELLOW SUBMARINE")
	requiredLength := 20
	paddedSlice := util.Pkcs7pad(input, requiredLength-len(input))
	_ = paddedSlice
}

// Implement CBC mode
// https://cryptopals.com/sets/2/challenges/10
func S2c10() {
	// Just verify that after encryption and decryption the result matches input
	input := util.ReadFileB64("./files/2-10.txt")
	key := []byte("YELLOW SUBMARINE")

	requiredPadding := len(key) - (len(input) % len(key))
	if requiredPadding == len(key) {
		requiredPadding = 0
	}
	paddedInput := util.Pkcs7pad(input, requiredPadding)

	iv := make([]byte, 16)

	encryptedText := util.CbcEncrypt(paddedInput, key, iv)
	plainText := util.CbcDecrypt(encryptedText, key, iv)

	// Both paddedInput and decrypted plainText are the same
	// This verifies that our cbcDecrypt function works
	verifyBytes := util.XorStuff(paddedInput, plainText)

	_ = verifyBytes // a whole bunch of zeroes

	// Bonus: Consider the input itself as encrypted text and decrypt it
	bonusPlainText := util.CbcDecrypt(paddedInput, key, iv)

	_ = bonusPlainText
}

// An ECB/CBC detection oracle
// https://cryptopals.com/sets/2/challenges/11
func S2c11() {
	// Choose an input that exposes ECB's weakness
	var plainText []byte
	for i := 0; i < 48; i++ {
		plainText = append(plainText, []byte("A")...)
	}

	nPreBytes := util.RandomInteger(5) + 5
	nPostBytes := util.RandomInteger(5) + 5
	plainText = append(util.RandomBytes(nPreBytes), plainText...)
	plainText = append(plainText, util.RandomBytes(nPostBytes)...)

	key := util.RandomBytes(16)

	requiredPadding := len(plainText) % len(key)
	if requiredPadding != 0 {
		plainText = util.Pkcs7pad(plainText, requiredPadding)
	}

	var cipherText []byte
	shouldECB := util.RandomInteger(50)%2 == 0
	fmt.Printf("Using ECB Mode -> %t\n", shouldECB)

	if shouldECB {
		cipherText = util.EcbEncrypt(plainText, key)
	} else {
		randomIv := util.RandomBytes(16)
		cipherText = util.CbcEncrypt(plainText, key, randomIv)
	}

	ecbDetected := util.IsECB(cipherText)
	fmt.Printf("Detected ECB Mode -> %t\n", ecbDetected)
}

func s2c12EncryptingBlackBox(input []byte) []byte {
	if util.Some16ByteKey == nil {
		util.Some16ByteKey = util.RandomBytes(16)
	}
	keySize := len(util.Some16ByteKey)

	bytesToAppend := util.ReadFileB64("./files/2-12-2.txt")
	input2 := append(input, bytesToAppend...)

	requiredPadding := keySize - (len(input2) % keySize)
	input3 := util.Pkcs7pad(input2, requiredPadding)

	return util.EcbEncrypt(input3, util.Some16ByteKey)
}

// Byte-at-a-time ECB decryption (Simple)
// https://cryptopals.com/sets/2/challenges/12
func S2c12() {
	// detect block size
	var detectedBlockSize int
	var lastOutputLength int

	for i := 1; ; i++ {
		input := bytes.Repeat([]byte("A"), i)
		output := s2c12EncryptingBlackBox(input)

		if len(output) > lastOutputLength && i > 1 {
			detectedBlockSize = len(output) - lastOutputLength
			break
		}
		lastOutputLength = len(output)
	}
	fmt.Printf("Detected block size: %d\n", detectedBlockSize)

	// detect ecb
	sampleInput := util.ReadFile("./files/2-12-1.txt")
	sampleOutput := s2c12EncryptingBlackBox(sampleInput)
	detectedECB := util.IsECB(bytes.Repeat(sampleOutput, 4))
	fmt.Printf("Detected ECB: %t\n", detectedECB)

	// calc total blocks to decode
	lenSecretString := len(s2c12EncryptingBlackBox(make([]byte, 0)))
	var nBlocksToDecode int
	if lenSecretString%detectedBlockSize == 0 { // hello? this will always be true!!
		nBlocksToDecode = lenSecretString / detectedBlockSize
	} else {
		nBlocksToDecode = (lenSecretString / detectedBlockSize) + 1
	}
	fmt.Printf("Number of blocks to decode: %d\n", nBlocksToDecode)

	// decrypt secret string
	var decryptedSecretString []byte
	for k := 0; k < nBlocksToDecode; k++ { // for each block
		for l := 0; l < detectedBlockSize; l++ { // for each byte
			commonBytes := bytes.Repeat([]byte("A"), detectedBlockSize-1-l)
			blockOfOutputCommonBytes := s2c12EncryptingBlackBox(commonBytes)[k*detectedBlockSize : (k+1)*detectedBlockSize]

			someMap := make(map[byte][]byte)
			for i := 0; i < 256; i++ { // for each possible byte value
				craftedInput := append(commonBytes, decryptedSecretString...)
				craftedInput = append(craftedInput, byte(i))
				blockOfOutput := s2c12EncryptingBlackBox(craftedInput)[k*detectedBlockSize : (k+1)*detectedBlockSize]
				someMap[byte(i)] = blockOfOutput
			}

			for k, v := range someMap {
				allBytesMatch := true
				for i, b := range v {
					if blockOfOutputCommonBytes[i] != b {
						allBytesMatch = false
						break
					}
				}
				if allBytesMatch {
					decryptedSecretString = append(decryptedSecretString, k)
					break
				}
			}
		}
	}
	fmt.Printf("Secret text:\n%s", string(decryptedSecretString))
}

func s2c13ParsingRoutine(s string) map[string]string {
	results := make(map[string]string)

	for _, pair := range strings.Split(s, "&") {
		segments := strings.Split(pair, "=")
		results[segments[0]] = segments[1]
	}

	return results
}

func s2c13ProfileFor(email string) string {
	sanitizedEmail := strings.ReplaceAll(email, "=", "")
	sanitizedEmail = strings.ReplaceAll(email, "&", "")

	profile := make(map[string]string)
	profile["email"] = sanitizedEmail
	profile["role"] = "user"
	profile["uid"] = "10"

	var s string
	for k, v := range profile {
		s += k + "=" + v + "&"
	}
	return s
}

// ECB cut-and-paste
// https://cryptopals.com/sets/2/challenges/13
func S2c13() {

	// len("email=") = 6
	input1 := "1234567890@examp.com" // len(input1) = 20
	// len("&role=") = 6

	profile1 := s2c13ProfileFor(input1)
	output1 := s2c12EncryptingBlackBox([]byte(profile1))

	input2 := "1234567890123456789012345@" + "admin"
	profile2 := s2c13ProfileFor(input2)
	output2 := s2c12EncryptingBlackBox([]byte(profile2))

	var craftedCipherText []byte
	craftedCipherText = append(craftedCipherText, output1[0:32]...) // first 2 blocks of output1
	craftedCipherText = append(craftedCipherText, output2[32:]...)  // rest of the block from output2
	plainText := util.EcbDecrypt(craftedCipherText, util.Some16ByteKey)

	// the duplication of role=admin&role=user can also be removed by modifying the inputs
	fmt.Println(string(plainText))
}

func s2c14EncryptingBlackBox(input []byte) []byte {
	if util.Some16ByteKey == nil {
		util.Some16ByteKey = util.RandomBytes(16)
	}
	keySize := len(util.Some16ByteKey)

	if util.SomeRandomPrefix == nil {
		util.SomeRandomPrefix = util.RandomBytes(9)
	}

	input2 := append(util.SomeRandomPrefix, input...)
	input2 = append(input2, util.ReadFile("./files/2-14.txt")...)

	requiredPadding := keySize - (len(input2) % keySize)
	input2 = util.Pkcs7pad(input2, requiredPadding)

	return util.EcbEncrypt(input2, util.Some16ByteKey)
}

// Byte-at-a-time ECB decryption (Harder)
// https://cryptopals.com/sets/2/challenges/14
func S2c14() {
	// detect block size
	var detectedBlockSize int
	{
		var lastOutputLength int
		for i := 1; ; i++ {
			input := bytes.Repeat([]byte("A"), i)
			output := s2c14EncryptingBlackBox(input)

			if len(output) > lastOutputLength && i > 1 {
				detectedBlockSize = len(output) - lastOutputLength
				break
			}
			lastOutputLength = len(output)
		}
		fmt.Printf("Detected block size: %d\n", detectedBlockSize)
	}

	// detect ecb
	{
		sampleOutput := s2c14EncryptingBlackBox(make([]byte, 0))
		detectedECB := util.IsECB(bytes.Repeat(sampleOutput, 4))
		fmt.Printf("Detected ECB: %t\n", detectedECB)
	}

	// detect length of random prefix
	// 1 what does a block full of "A" look like?
	var controlledBlock []byte
	{
		nBlocks := 5
		input := bytes.Repeat([]byte("A"), detectedBlockSize*nBlocks)
		output := s2c14EncryptingBlackBox(input)

		// there must be nBlocks - 2 consecutive blocks which are same
		nBlocksMatched := 0
		for i := 0; i+detectedBlockSize < len(output); i = i + detectedBlockSize {
			j := 0
			for {
				if output[i+j] != output[i+detectedBlockSize+j] {
					break
				}
				if j < detectedBlockSize-1 {
					j = j + 1
				} else {
					break
				}
			}
			if j == detectedBlockSize-1 {
				nBlocksMatched += 1
			} else {
				if nBlocksMatched == nBlocks-2 {
					controlledBlock = output[i : i+detectedBlockSize]
					break
				} else {
					nBlocksMatched = 0
				}
			}
		}
	}

	// 2 add control bytes and find a control block
	var randomPrefixLength int
	{
		for i := detectedBlockSize; ; i++ {
			input := bytes.Repeat([]byte("A"), i)
			output := s2c14EncryptingBlackBox(input)

			done := false
			for j := 0; j+detectedBlockSize < len(output); j = j + detectedBlockSize {
				k := 0
				for {
					if output[j+k] != controlledBlock[k] {
						break
					}
					if k < detectedBlockSize-1 {
						k++
					} else {
						break
					}
				}
				if k == detectedBlockSize-1 {
					// j is start index of control block
					randomPrefixLength = j - (i - detectedBlockSize)
					done = true
					break
				}
			}
			if done {
				break
			}
		}
		fmt.Printf("Random prefix length: %d\n", randomPrefixLength)
	}

	// calc total blocks to decode
	var nBlocksToDecode int
	var nBlocksTakenByPrefix int
	nControlBytes := 0
	{
		nBlocksTakenByPrefix = randomPrefixLength / detectedBlockSize
		if randomPrefixLength%detectedBlockSize != 0 {
			nBlocksTakenByPrefix++
			nControlBytes = detectedBlockSize - (randomPrefixLength % detectedBlockSize)
		}
		lenSecretString := len(s2c14EncryptingBlackBox(make([]byte, nControlBytes)))
		nBlocksToDecode = (lenSecretString / detectedBlockSize) - nBlocksTakenByPrefix
		fmt.Printf("Number of blocks to decode: %d\n", nBlocksToDecode)
	}

	var decryptedSecretString []byte
	for k := 0; k < nBlocksToDecode; k++ { // for each block
		for l := 0; l < detectedBlockSize; l++ { // for each byte
			commonBytes := bytes.Repeat([]byte("A"), nControlBytes+detectedBlockSize-1-l)
			blockOfOutputCommonBytes := s2c14EncryptingBlackBox(commonBytes)
			blockOfOutputCommonBytes = blockOfOutputCommonBytes[nBlocksTakenByPrefix*detectedBlockSize:]
			blockOfOutputCommonBytes = blockOfOutputCommonBytes[k*detectedBlockSize : (k+1)*detectedBlockSize]

			someMap := make(map[byte][]byte)
			for i := 0; i < 256; i++ { // for each possible byte value
				craftedInput := append(commonBytes, decryptedSecretString...)
				craftedInput = append(craftedInput, byte(i))
				blockOfOutput := s2c14EncryptingBlackBox(craftedInput)
				blockOfOutput = blockOfOutput[nBlocksTakenByPrefix*detectedBlockSize:]
				blockOfOutput = blockOfOutput[k*detectedBlockSize : (k+1)*detectedBlockSize]
				someMap[byte(i)] = blockOfOutput
			}

			for k, v := range someMap {
				allBytesMatch := true
				for i, b := range v {
					if blockOfOutputCommonBytes[i] != b {
						allBytesMatch = false
						break
					}
				}
				if allBytesMatch {
					decryptedSecretString = append(decryptedSecretString, k)
					break
				}
			}
		}

	}
	fmt.Printf("Secret text: %s", string(decryptedSecretString))
}

// PKCS#7 padding validation
// https://cryptopals.com/sets/2/challenges/15
func S2c15() {
	input := []byte("\x04\x04\x194\x02")
	output, err := util.StripValidPadding(input)
	if err != nil {
		panic(err)
	} else {
		fmt.Print(output)
	}
}

func s2c16func1(input string) []byte {
	prepend := "comment1=cooking%20MCs;userdata="
	append := ";comment2=%20like%20a%20pound%20of%20bacon"

	escapedInput := strings.ReplaceAll(input, ";", "\\;")
	escapedInput = strings.ReplaceAll(escapedInput, "=", "\\=")

	fullStr := prepend + escapedInput + append

	var requiredPadding int
	if len(fullStr)%16 == 0 {
		requiredPadding = 0
	} else {
		requiredPadding = 16 - (len(fullStr) % 16)
	}
	paddedStr := util.Pkcs7pad([]byte(fullStr), requiredPadding)
	if util.Some16ByteKey == nil {
		util.Some16ByteKey = bytes.Repeat([]byte("B"), 16)
		util.Some16ByteIV = bytes.Repeat([]byte("A"), 16)
	}

	return util.CbcEncrypt(paddedStr, util.Some16ByteKey, util.Some16ByteIV)
}

func s2c16func2(input []byte) bool {
	plainTextBytes := util.CbcDecrypt(input, util.Some16ByteKey, util.Some16ByteIV)
	adminRegex := regexp.MustCompile(`[^\\];admin=true;`)
	return adminRegex.Match(plainTextBytes)
}

// CBC bitflipping attacks
// https://cryptopals.com/sets/2/challenges/16
func S2c16() {
	encryptedText := s2c16func1("johnjohnjohnjohn;admi=true")

	// turn escape character \ before ; into anything else
	// turn escape character \ before = into n
	for i := 0; i < 255; i++ {
		for j := 0; j < 255; j++ {
			moddedEncr := encryptedText[:32]
			moddedEncr = append(moddedEncr, byte(i))
			moddedEncr = append(moddedEncr, encryptedText[33:38]...)
			moddedEncr = append(moddedEncr, byte(j))
			moddedEncr = append(moddedEncr, encryptedText[39:]...)

			isAdmin := s2c16func2(moddedEncr)
			if isAdmin {
				fmt.Printf("%d %d\n", i, j)
				// there will be multiple solutions
				return
			}
		}

	}
}
