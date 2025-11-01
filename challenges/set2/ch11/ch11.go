package ch11

import (
	"bytes"
	"crypto/aes"
	crand "crypto/rand"
	"fmt"
	"io"
	"math/big"

	"cryptopals/challenges/set1/ch2"
	"cryptopals/challenges/set2/ch9"
)

// secureRandomBytes returns n crypto-random bytes.
func secureRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// secureRandomInt returns a random int in [0, max).
func secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("invalid max")
	}
	nBig, err := crand.Int(crand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()), nil
}

// generateRandomAESKey returns a cryptographically secure AES key of length 16.
func GenerateRandomAESKey() ([]byte, error) {
	return secureRandomBytes(16)
}

// writeAESEncryption: ECB encrypt (expects plaintext bytes; padding applied inside).
func WriteAESEncryption(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	padded, err := ch9.PKCSPadding(plaintext, bs)
	if err != nil {
		return nil, fmt.Errorf("pad: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	for start := 0; start < len(padded); start += bs {
		end := start + bs
		block.Encrypt(ciphertext[start:end], padded[start:end])
	}
	return ciphertext, nil
}

// encryptAESCBC: CBC encryption using your encryptAESCBC semantics (expects plaintext bytes).
func encryptAESCBC(plaintext []byte, key, iv []byte) ([]byte, error) {
	// reuse the implementation you already wrote, but ensure it accepts []byte plaintext.
	const blockSize = 16
	if len(iv) != blockSize {
		return nil, fmt.Errorf("iv must be %d bytes", blockSize)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}
	padded, err := ch9.PKCSPadding(plaintext, blockSize)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	prev := make([]byte, blockSize)
	copy(prev, iv)
	bs := block.BlockSize()
	for i := 0; i < len(padded); i += bs {
		pBlock := padded[i : i+bs]
		xored, err := ch2.Buf2XOR(pBlock, prev)
		if err != nil {
			return nil, fmt.Errorf("xor failed: %w", err)
		}
		cBlock := make([]byte, bs)
		block.Encrypt(cBlock, xored)
		if _, err := out.Write(cBlock); err != nil {
			return nil, err
		}
		copy(prev, cBlock)
	}
	return out.Bytes(), nil
}

// EncryptionOracle produces ciphertext for the challenge:
// - prepends 5-10 random bytes and appends 5-10 random bytes
// - chooses ECB or CBC at random
// Returns: ciphertext, key, iv (iv==nil for ECB), modeIsECB (true if ECB), error
func EncryptionOracle(plaintext []byte) (ciphertext []byte, key []byte, iv []byte, modeIsECB bool, err error) {
	// 1) generate random key
	key, err = GenerateRandomAESKey()
	if err != nil {
		return nil, nil, nil, false, err
	}

	// 2) random 5-10 byte prefix and suffix
	prefixLen, err := secureRandomInt(6) // returns 0..5
	if err != nil {
		return nil, nil, nil, false, err
	}
	prefixLen += 5 // now 5..10
	suffixLen, err := secureRandomInt(6)
	if err != nil {
		return nil, nil, nil, false, err
	}
	suffixLen += 5

	prefix, err := secureRandomBytes(prefixLen)
	if err != nil {
		return nil, nil, nil, false, err
	}
	suffix, err := secureRandomBytes(suffixLen)
	if err != nil {
		return nil, nil, nil, false, err
	}

	// combined plaintext
	input := append(prefix, plaintext...)
	input = append(input, suffix...)

	// 3) randomly choose ECB or CBC
	choice, err := secureRandomInt(2) // 0 or 1
	if err != nil {
		return nil, nil, nil, false, err
	}
	if choice == 0 {
		// ECB
		ct, err := WriteAESEncryption(input, key)
		if err != nil {
			return nil, nil, nil, false, err
		}
		return ct, key, nil, true, nil
	}

	// CBC
	iv, err = secureRandomBytes(16)
	if err != nil {
		return nil, nil, nil, false, err
	}
	ct, err := encryptAESCBC(input, key, iv)
	if err != nil {
		return nil, nil, nil, false, err
	}
	return ct, key, iv, false, nil
}

