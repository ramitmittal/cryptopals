package set3

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"ramitmittal.com/cryptopals/internal/util"
	"ramitmittal.com/cryptopals/internal/util/prng"
)

func s3c17First() ([]byte, []byte) {
	util.Some16ByteKey = util.RandomBytes(16)
	util.Some16ByteIV = util.RandomBytes(16)

	fileContent := util.ReadFile("./files/3-17.txt")
	util.SomeStringSlice = strings.Split(string(fileContent), "\n")
	randomInt := int(util.RandomInteger(int64(len(util.SomeStringSlice))))
	selectedLine := util.SomeStringSlice[randomInt]

	fmt.Printf("Selected line: %s\n", selectedLine)

	requiredPadding := len(util.Some16ByteKey) - (len(selectedLine) % len(util.Some16ByteKey))
	paddedLine := util.Pkcs7pad([]byte(selectedLine), requiredPadding)

	return util.CbcEncrypt(paddedLine, util.Some16ByteKey, util.Some16ByteIV), util.Some16ByteIV
}

func s3c17Second(encryptedText, iv []byte) bool {
	paddedLine := util.CbcDecrypt(encryptedText, util.Some16ByteKey, iv)
	_, err := util.StripValidPadding(paddedLine)
	return err == nil
}

// The CBC padding oracle
// https://cryptopals.com/sets/3/challenges/17
func S3c17() {
	cipherText, iv := s3c17First()

	var paddedPlainText []byte
	nBlocks := len(cipherText) / 16

	for i := nBlocks - 1; i > 0; i-- {
		// i = 4 -> we are trying to decrypt 5th block

		var decryptedBlock []byte
		for j := 15; j > -1; j-- {
			blockStart := i * 16 // 64 -> start index of block we are trying to decrypt

			var modifiedCt []byte
			modifiedCt = append(modifiedCt, cipherText[0:blockStart-16+j]...) // 63 bytes -> 0 to 62 index
			modifiedCt = append(modifiedCt, byte(0))                          // 64th byte -> 63th index

			paddingByte := byte(16 - j)

			corruptedDecryptedBytes := util.XorStuff(decryptedBlock, bytes.Repeat([]byte{paddingByte}, len(decryptedBlock)))
			if len(corruptedDecryptedBytes) > 0 {
				corruptedDecryptedBytes = util.XorStuff(corruptedDecryptedBytes, cipherText[blockStart-16+j+1:blockStart-16+j+1+len(corruptedDecryptedBytes)])
			}

			modifiedCt = append(modifiedCt, corruptedDecryptedBytes...)
			modifiedCt = append(modifiedCt, cipherText[blockStart:blockStart+16]...)

			var valuesThatGaveValidPadding []byte
			for k := 0; k < 256; k++ {
				modifiedCt[blockStart-16+j] = byte(k)
				if s3c17Second(modifiedCt, iv) {
					valuesThatGaveValidPadding = append(valuesThatGaveValidPadding, byte(k))
				}
			}
			if len(valuesThatGaveValidPadding) > 1 {
				for _, l := range valuesThatGaveValidPadding {
					modifiedCt[blockStart-17+j] = byte(201)
					modifiedCt[blockStart-16+j] = l
					if s3c17Second(modifiedCt, iv) {
						newByte := l ^ byte(paddingByte) ^ cipherText[blockStart-16+j]
						decryptedBlock = append([]byte{newByte}, decryptedBlock...)
						break
					}
				}
			} else if len(valuesThatGaveValidPadding) == 1 {
				newByte := valuesThatGaveValidPadding[0] ^ byte(paddingByte) ^ cipherText[blockStart-16+j]
				decryptedBlock = append([]byte{newByte}, decryptedBlock...)
			} else {
				fmt.Println("noooo")
			}
		}
		paddedPlainText = append(decryptedBlock, paddedPlainText...)
	}

	// to decrypt the first block do the same with IV?
	fmt.Printf("Decrypted line: %s\n", paddedPlainText)
}

// Implement CTR, the stream cipher mode
// https://cryptopals.com/sets/3/challenges/18
func S3c18() {
	key := []byte("YELLOW SUBMARINE")
	nonce := bytes.Repeat([]byte{byte(0)}, 8)

	input := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	inputBytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		panic(err)
	}

	plainText := util.CtrEncrypt(inputBytes, key, nonce)

	_ = plainText
}

// Break fixed-nonce CTR mode using substitutions
// https://cryptopals.com/sets/3/challenges/19
func s3c19() {
	// Just go to S3c20
}

// Break fixed-nonce CTR statistically
// https://cryptopals.com/sets/3/challenges/20
func S3c20() {
	plainLines := util.ReadFileOfB64Strings("files/3-19.txt")

	nonce := bytes.Repeat([]byte{byte(0)}, 8)
	key := util.RandomBytes(16)

	lenSmallest := 4200000 // random large number
	var encryptedLines [][]byte
	for _, pl := range plainLines {
		el := util.CtrEncrypt(pl, key, nonce)
		encryptedLines = append(encryptedLines, el)
		if len(el) < lenSmallest {
			lenSmallest = len(el)
		}
	}

	// adapted from s1c6
	// lenSmallest is the keySize

	var inputBlocks [][]byte
	for _, el := range encryptedLines {
		inputBlocks = append(inputBlocks, el[0:lenSmallest])
	}
	var transposedInputBlocks [][]byte // chosenKeySize blocks of length n
	for blockNum := 0; blockNum < lenSmallest; blockNum++ {
		var newBlock []byte

		for someVar := 0; someVar < len(inputBlocks); someVar++ {
			newBlock = append(newBlock, inputBlocks[someVar][blockNum])
		}

		transposedInputBlocks = append(transposedInputBlocks, newBlock)
	}

	var crackedKey []byte
	for _, transposedInputBlock := range transposedInputBlocks {
		_, keyForBlock := util.SingleByteXor(transposedInputBlock)
		crackedKey = append(crackedKey, byte(keyForBlock.Key))
	}

	plainText := util.RepeatingKeyXor(inputBlocks[0], crackedKey)
	fmt.Print(string(plainText))
}

// Implement the MT19937 Mersenne Twister RNG
// https://cryptopals.com/sets/3/challenges/21
func S3c21() {
	tw := prng.New(404)

	fmt.Println("1000 outputs")
	for i := 0; i < 1000; i++ {
		fmt.Printf("%10d ", tw.ExtractNumber())
		if i%5 == 4 {
			fmt.Println("")
		}
	}
}

func s3c22Routine() uint32 {
	someTime := time.Duration(rand.Intn(60)) * time.Second
	fmt.Printf("Waiting for %v\n", someTime)
	<-time.After(someTime)

	tw := prng.New(uint32(time.Now().Unix()))

	someMoreTime := time.Duration(rand.Intn(60)) * time.Second
	fmt.Printf("Waiting for %v\n", someMoreTime)
	<-time.After(someMoreTime)

	return tw.ExtractNumber()
}

// Crack an MT19937 seed
// https://cryptopals.com/sets/3/challenges/22
func S3c22() {
	n := s3c22Routine()

	fmt.Printf("Number is: %d\nStarting brute force\n", n)

	// Could start from 0 but we can start from now and move backwards
	seed := uint32(time.Now().Unix())
	for {
		tw := prng.New(seed)
		if tw.ExtractNumber() == n {
			fmt.Printf("Cracked seed is: %d\n", seed)
			break
		}
		seed -= 1
	}
}

// Solve the equation
// y = y0 ^ (y >> n)
// for y0
func s3c23UnshiftLeft(y uint32, n int) uint32 {
	initialMask := uint32(0)
	m := n
	y0 := uint32(0)
	for {
		maskForStep := uint32(0xFFFFFFFF<<(32-m)) ^ initialMask
		yx := y0 >> n
		y0 = y0 ^ (y^yx)&maskForStep

		if m >= 32 {
			break
		}
		initialMask = initialMask | maskForStep
		if m+n < 32 {
			m = m + n
		} else {
			m = m + (32 - m)
		}
	}
	return y0
}

// Solve the equation
// y = y0 ^ ((y0 << t) & c)
// for y0
func s3c23UnshiftRight(y uint32, t int, c uint32) uint32 {
	initialMask := uint32(0)
	m := t
	y0 := uint32(0)
	for {
		maskForStep := uint32(0xFFFFFFFF>>(32-m)) ^ initialMask
		yx := (y0 << t) & c
		y0 = y0 ^ (y^yx)&maskForStep

		if m >= 32 {
			break
		}
		initialMask = initialMask | maskForStep
		if m+t < 32 {
			m = m + t
		} else {
			m = m + (32 - m)
		}
	}
	return y0
}

func s3c23Untemper(y4 uint32) uint32 {
	y3 := s3c23UnshiftLeft(y4, 18)
	y2 := s3c23UnshiftRight(y3, 15, 0xEFC60000)
	y1 := s3c23UnshiftRight(y2, 7, 0x9D2C5680)
	return s3c23UnshiftLeft(y1, 11)
}

// Clone an MT19937 RNG from its output
// https://cryptopals.com/sets/3/challenges/23
func S3c23() {
	tw := prng.New(47)

	var untemperedState [624]uint32
	for i := 0; i < 624; i++ {
		temperedNum := tw.ExtractNumber()
		untemperedState[i] = s3c23Untemper(temperedNum)
	}

	clonedTwister := prng.New(1)
	clonedTwister.Mt = untemperedState
	clonedTwister.Index = 624

	for i := 0; i < 5; i++ {
		fmt.Printf("original: %d, cloned: %d\n", tw.ExtractNumber(), clonedTwister.ExtractNumber())
	}
}

func s3c24Check1() {
	seed := uint16(404)

	pt := "Kono Dio Da! Kono Dio Da! Kono Dio Da! Kono Dio Da! Kono Dio Da! "
	ct := util.MT19937Encrypt([]byte(pt), seed)
	pt2 := util.MT19937Encrypt(ct, seed)
	fmt.Println(string(pt2))
}

func s3c24Check2() {
	// most solutions on the internet assume that the random prefix will remain the same across multiple encryptions
	// I don't think that's what the challenge text says

	seed := uint16(404)

	plainText := bytes.Repeat([]byte("A"), 14)

	// get a cipherText that has size a multiple of 20
	var chosenCT []byte
	for {
		randomPrefix := util.RandomBytes(util.RandomInteger(6))
		finalPlainText := append(randomPrefix, plainText...)
		ct := util.MT19937Encrypt(finalPlainText, seed)

		if len(ct)%4 == 0 {
			chosenCT = ct
			break
		}
	}

	// last 4 bytes of chosenCT were "AAAA" and they were xored by a single number from PRNG
	ctSize := len(chosenCT)
	generatedNumberBytes := util.XorStuff(chosenCT[ctSize-4:ctSize], []byte("AAAA"))
	generatedNumber := binary.LittleEndian.Uint32(generatedNumberBytes)

	// generatedNumber is the ith number from PRNG
	indexOfGeneratedNumber := ctSize / 4

	for i := 0; i < int(math.Pow(2, 16)); i++ {
		tw := prng.New(uint32(i))
		for j := 0; j < indexOfGeneratedNumber-1; j++ {
			tw.ExtractNumber()
		}

		ithNum := tw.ExtractNumber()
		if ithNum == generatedNumber {
			fmt.Printf("detected seed: %d, original seed: %d\n", i, seed)
			return
		}
	}
}

// Create the MT19937 stream cipher and break it
// https://cryptopals.com/sets/3/challenges/24
func S3c24() {
	s3c24Check2()
}
