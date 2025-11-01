package ch12

import (
	"cryptopals/challenges/set2/ch11"
	"encoding/base64"
)

var globalKey []byte

var secretSuffix []byte

func init() {
	decoded, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	secretSuffix = decoded
}

func generateKEY() ([]byte, error) {

	if globalKey == nil {
		key, err := ch11.GenerateRandomAESKey()
		if err != nil {
			return nil, err
		}
		globalKey = key
	}
	return globalKey, nil
}

func ECBOracle(input []byte) ([]byte, error) {
	key, _ := generateKEY()

	combined := append(input, secretSuffix...)
	ciphertext, err := ch11.WriteAESEncryption(combined, key)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
