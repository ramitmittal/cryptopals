package set1

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"sort"

	"ramitmittal.com/cryptopals/internal/util"
)

// Convert a hex string to base64
// https://cryptopals.com/sets/1/challenges/1
func S1c1() {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	bytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	output := base64.StdEncoding.EncodeToString(bytes)

	_ = output
}

// Fixed XOR
// https://cryptopals.com/sets/1/challenges/2
func S1c2() {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"

	b1, err := hex.DecodeString(input1)
	if err != nil {
		panic(err)
	}
	b2, err := hex.DecodeString(input2)
	if err != nil {
		panic(err)
	}
	outBytes := util.XorStuff(b1, b2)
	output := hex.EncodeToString(outBytes)

	_ = output
}

// Single-byte XOR cipher
// https://cryptopals.com/sets/1/challenges/3
func S1c3() {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	plainBytes, _ := util.SingleByteXor(inputBytes)
	plainText := string(plainBytes)

	_ = plainText
}

// A "hyper" version of s1c3
// https://cryptopals.com/sets/1/challenges/4
func S1c4() {
	lines := util.ReadFileOfHexStrings("./files/1-4.txt")
	var bestScoresForEach []util.HyperKeyScore

	for idx, line := range lines {
		decryptedText, ks := util.SingleByteXor(line)
		hks := util.HyperKeyScore{
			DecryptedText: string(decryptedText),
			Line:          idx,
			Key:           ks.Key,
			Score:         ks.Score,
		}
		bestScoresForEach = append(bestScoresForEach, hks)
	}

	sort.Slice(bestScoresForEach, func(i, j int) bool {
		return bestScoresForEach[i].Score > bestScoresForEach[j].Score
	})
	plainText := (bestScoresForEach[0].DecryptedText)

	_ = plainText
}

// Implement repeating-key XOR
// https://cryptopals.com/sets/1/challenges/5
func S1c5() {
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"

	result := util.RepeatingKeyXor([]byte(input), []byte(key))
	resultAsHex := hex.EncodeToString(result)

	_ = resultAsHex
}

// Break repeating-key XOR
// https://cryptopals.com/sets/1/challenges/6
func S1c6() {
	input := util.ReadFileB64("./files/1-6.txt")

	// 1 - guess key size
	var averageEditDistances []util.KeyScore
	for keySize := 2; keySize < 40; keySize++ {
		var inputBlocks [][]byte
		for blockNum := 0; (blockNum * keySize) < len(input)-keySize; blockNum++ {
			inputBlocks = append(inputBlocks, input[blockNum*keySize:blockNum*keySize+keySize])
		}

		editDistanceSum := 0.0
		for blockNum := 0; blockNum < len(inputBlocks)-1; blockNum++ {
			editDistance := util.HammingDist(inputBlocks[blockNum], inputBlocks[blockNum+1])
			normalizedEditDistance := editDistance / keySize
			editDistanceSum += float64(normalizedEditDistance)
		}
		averageEditDistance := editDistanceSum / float64(len(inputBlocks)-1)
		averageEditDistances = append(averageEditDistances, util.KeyScore{Key: keySize, Score: float64(averageEditDistance)})
	}

	sort.Slice(averageEditDistances, func(i, j int) bool {
		return averageEditDistances[i].Score < averageEditDistances[j].Score
	})

	chosenKeySize := averageEditDistances[0].Key

	// 2 - break and transpose

	var inputBlocks [][]byte // n blocks of length = chosenKeySize
	// we ran a similar loop in the last step and could have used the same results but IDC for now
	for blockNum := 0; (blockNum * chosenKeySize) < len(input)-chosenKeySize; blockNum++ {
		inputBlocks = append(inputBlocks, input[blockNum*chosenKeySize:blockNum*chosenKeySize+chosenKeySize])
	}

	var transposedInputBlocks [][]byte // chosenKeySize blocks of length n
	for blockNum := 0; blockNum < chosenKeySize; blockNum++ {
		var newBlock []byte

		for someVar := 0; someVar < len(inputBlocks); someVar++ {
			newBlock = append(newBlock, inputBlocks[someVar][blockNum])
		}

		transposedInputBlocks = append(transposedInputBlocks, newBlock)
	}

	// 3 - single byte xor detection for each block
	var key []byte
	for _, transposedInputBlock := range transposedInputBlocks {
		_, keyForBlock := util.SingleByteXor(transposedInputBlock)
		key = append(key, byte(keyForBlock.Key))
	}

	// 4 - try decryption with assembled key
	plainText := util.RepeatingKeyXor(input, key)
	output := string(plainText)

	_ = output
}

// AES in ECB mode
// https://cryptopals.com/sets/1/challenges/7
func S1c7() {
	input := util.ReadFileB64("./files/1-7.txt")
	key := []byte("YELLOW SUBMARINE")

	plainText := make([]byte, len(input))
	keySize := len(key)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	for i := 0; i+keySize <= len(input); i = i + keySize {
		cipher.Decrypt(plainText[i:i+keySize], input[i:i+keySize])
	}

	output := string(plainText)

	_ = output
}

// Detect AES in ECB mode
// https://cryptopals.com/sets/1/challenges/8
func S1c8() {
	input := util.ReadFileOfHexStrings("./files/1-8.txt")

	var matchedIdx int
	for idx, line := range input {
		if util.IsECB(line) {
			matchedIdx = idx
			break
		}
	}

	_ = matchedIdx
}
