package util

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"strings"
)

// Read a file of newline separated base64 strings decoding each to byte slice
func ReadFileOfB64Strings(filename string) [][]byte {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	rawString := string(raw)
	trailingNewlinesRemoved := strings.Trim(rawString, "\n")
	hexEncodedStrings := strings.Split(trailingNewlinesRemoved, "\n")

	var byteStrings [][]byte
	for _, hexEncodedString := range hexEncodedStrings {
		lineAsBytes, err := base64.StdEncoding.DecodeString(hexEncodedString)
		if err != nil {
			panic(err)
		}
		byteStrings = append(byteStrings, lineAsBytes)
	}
	return byteStrings
}

// Read a file of newline separated hex strings decoding each to byte slice
func ReadFileOfHexStrings(filename string) [][]byte {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	rawString := string(raw)
	trailingNewlinesRemoved := strings.Trim(rawString, "\n")
	hexEncodedStrings := strings.Split(trailingNewlinesRemoved, "\n")

	var byteStrings [][]byte
	for _, hexEncodedString := range hexEncodedStrings {
		lineAsBytes, err := hex.DecodeString(hexEncodedString)
		if err != nil {
			panic(err)
		}
		byteStrings = append(byteStrings, lineAsBytes)
	}
	return byteStrings
}

// Read a file and decode base64 content to bytes
func ReadFileB64(filename string) []byte {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	rawString := string(raw)
	newLinesRemoved := strings.ReplaceAll(rawString, "\n", "")

	bytes, err := base64.StdEncoding.DecodeString(newLinesRemoved)
	if err != nil {
		panic(err)
	}

	return bytes
}

// Read a file
func ReadFile(filename string) []byte {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return raw
}
