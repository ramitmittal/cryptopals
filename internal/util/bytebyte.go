package util

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf8"

	"ramitmittal.com/cryptopals/internal/util/prng"
)

func countSetBits(b byte) int {
	nani := []byte{
		0b00000001,
		0b00000010,
		0b00000100,
		0b00001000,
		0b00010000,
		0b00100000,
		0b01000000,
		0b10000000,
	}

	total := 0
	for _, na := range nani {
		if (b & na) > 0 {
			total += 1
		}
	}

	return total
}

func HammingDist(b1 []byte, b2 []byte) int {
	total := 0

	for i := 0; i < len(b1); i++ {
		xoredByte := b1[i] ^ b2[i]
		total += countSetBits(xoredByte)
	}

	return total
}

func Pkcs7pad(input []byte, requiredPadding int) []byte {
	paddedSlice := input

	for i := 0; i < requiredPadding; i++ {
		paddedSlice = append(paddedSlice, byte(requiredPadding))
	}
	return paddedSlice
}

func CbcEncrypt(paddedPlainText []byte, key []byte, iv []byte) []byte {
	keyLength := len(key)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encryptedText := make([]byte, len(paddedPlainText))
	for i := 0; i+keyLength <= len(paddedPlainText); i = i + keyLength {
		intermediateResult := XorStuff(paddedPlainText[i:i+keyLength], iv)
		cipher.Encrypt(encryptedText[i:i+keyLength], intermediateResult)
		iv = encryptedText[i : i+keyLength]
	}

	return encryptedText
}

func CbcDecrypt(encryptedText []byte, key []byte, iv []byte) []byte {
	keyLength := len(key)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var plainText []byte
	for i := 0; i+keyLength <= len(encryptedText); i = i + keyLength {
		intermediateResult := make([]byte, keyLength)
		cipher.Decrypt(intermediateResult, encryptedText[i:i+keyLength])
		for _, plainTextByte := range XorStuff(intermediateResult, iv) {
			plainText = append(plainText, plainTextByte)
		}
		iv = encryptedText[i : i+keyLength]
	}

	return plainText
}

func EcbEncrypt(plainText []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cipherText := make([]byte, len(plainText))
	keySize := len(key)

	for i := 0; i+keySize <= len(plainText); i = i + keySize {
		cipher.Encrypt(cipherText[i:i+keySize], plainText[i:i+keySize])
	}

	return cipherText
}

func EcbDecrypt(cipherText []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	plainText := make([]byte, len(cipherText))
	keySize := len(key)

	for i := 0; i+keySize <= len(cipherText); i = i + keySize {
		cipher.Decrypt(plainText[i:i+keySize], cipherText[i:i+keySize])
	}

	return plainText
}

func XorStuff(a []byte, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

type KeyScore struct {
	Key   int
	Score float64
}

type HyperKeyScore struct {
	DecryptedText string
	Line          int
	Key           int
	Score         float64
}

func RepeatingKeyXor(input []byte, key []byte) []byte {
	var result []byte

	for idx, inputByte := range input {
		var keyByte byte
		if idx < len(key) {
			keyByte = key[idx]
		} else {
			keyByte = key[idx%len(key)]
		}
		result = append(result, inputByte^keyByte)
	}

	return result
}

func SingleByteXor(inputBytes []byte) ([]byte, KeyScore) {
	// xor input with all possible keys
	var decryptedRunesArr [256][]rune
	for possibleKey := 0; possibleKey < 256; possibleKey++ {
		keyAsByte := byte(possibleKey)

		var inputXoredWithKey []byte
		for _, inputByte := range inputBytes {
			inputXoredWithKey = append(inputXoredWithKey, inputByte^keyAsByte)
		}

		var decryptedRunes []rune
		i := 0
		for i < len(inputXoredWithKey) {
			inputSlice := inputXoredWithKey[i:]
			r, size := utf8.DecodeRune(inputSlice)
			decryptedRunes = append(decryptedRunes, r)
			i += size
		}

		decryptedRunesArr[possibleKey] = decryptedRunes
	}

	// score all xor results
	var decryptionScores []KeyScore

	characterScores := map[rune]float64{
		'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
		'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
		'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
		'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
		'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
		'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
		'y': .01974, 'z': .00074, ' ': .13000,
	}

	for idx, decryptedRunes := range decryptedRunesArr {
		stringScore := 0.0
		for _, oneRune := range decryptedRunes {
			charScore, _ := characterScores[oneRune]
			stringScore += charScore
		}
		decryptionScores = append(decryptionScores, KeyScore{
			Key:   idx,
			Score: stringScore,
		})
	}

	sort.Slice(decryptionScores, func(i, j int) bool {
		return decryptionScores[i].Score > decryptionScores[j].Score
	})

	mostProbableRunes := decryptedRunesArr[decryptionScores[0].Key]
	return []byte(string(mostProbableRunes)), decryptionScores[0]
}

func IsECB(input []byte) bool {
	// divide input into blocks of 16 bytes
	var blocks [][]byte

	for i := 0; i+16 <= len(input); i = i + 16 {
		blocks = append(blocks, input[i:i+16])
	}

	// compare blocks
	for i := 0; i < len(blocks); i++ {
		for j := i + 1; j < len(blocks); j++ {
			if HammingDist(blocks[i], blocks[j]) == 0 {
				return true
			}
		}
	}
	return false
}

func StripValidPadding(input []byte) ([]byte, error) {
	// as per the instructions this function expects that the string will always have padding

	lastByte := input[len(input)-1]
	nBytesMatched := 1

	for i := len(input) - 2; i > -1; i-- {
		if input[i] == lastByte {
			nBytesMatched += 1
		} else {
			break
		}
	}

	if int(lastByte) == nBytesMatched {
		return input[0 : len(input)-nBytesMatched], nil
	}

	return nil, fmt.Errorf("string had %d bytes with value %d", nBytesMatched, lastByte)
}

func CtrEncrypt(plainText []byte, key []byte, nonce []byte) []byte {
	// nonce will be half of len(key)
	// counter will run till 255

	keySize := len(key)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var cipherText []byte
	nBytesTaken := 0
	counter := 0

	for {
		counterBytes := append(nonce, bytes.Repeat([]byte{byte(0)}, keySize/2)...)
		counterBytes[keySize/2] = byte(counter)

		encryptedCounter := make([]byte, keySize)
		cipher.Encrypt(encryptedCounter, counterBytes)

		var plainTextBlock []byte
		if nBytesTaken+keySize <= len(plainText) {
			plainTextBlock = plainText[nBytesTaken : nBytesTaken+keySize]
		} else {
			remainingBytes := len(plainText) - nBytesTaken
			plainTextBlock = plainText[nBytesTaken : nBytesTaken+remainingBytes]
		}

		cipherText = append(cipherText, XorStuff(plainTextBlock, encryptedCounter)...)

		counter += 1
		nBytesTaken += keySize
		if nBytesTaken >= len(plainText) {
			break
		}
	}

	return cipherText
}

func MT19937Encrypt(plainText []byte, seed uint16) []byte {
	keySize := 4
	tw := prng.New(uint32(seed))

	var cipherText []byte
	nBytesTaken := 0

	for {
		var plainTextBlock []byte
		if nBytesTaken+keySize <= len(plainText) {
			plainTextBlock = plainText[nBytesTaken : nBytesTaken+keySize]
		} else {
			remainingBytes := len(plainText) - nBytesTaken
			plainTextBlock = plainText[nBytesTaken : nBytesTaken+remainingBytes]
		}

		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, tw.ExtractNumber())

		cipherText = append(cipherText, XorStuff(plainTextBlock, buf)...)

		nBytesTaken += keySize
		if nBytesTaken >= len(plainText) {
			break
		}
	}

	return cipherText
}
