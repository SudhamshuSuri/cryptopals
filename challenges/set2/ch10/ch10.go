package ch10

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"

	"cryptopals/challenges/set1/ch2"
)

func DecryptCBC(filepath string, key, iv []byte) ([]byte, error) {
	blockSize := 16

	if len(iv) != blockSize{
		return nil, fmt.Errorf("Key must be of blocksize (got %d)", len(iv))
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32{
		return nil, fmt.Errorf("Key must be of 16, 24, 32 bytes (got %d)", len(key))
	}

	raw, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("Error occured when opening file %s", err)
	}

	strip  := bytes.ReplaceAll(raw, []byte("\n"), []byte(""))
	ciphertext, err := base64.RawStdEncoding.DecodeString(string(strip))

	// ciphertext length must be multiple of block size
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(ciphertext), blockSize)
	}

	// prepare AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	// decryption loop
	var plaintext bytes.Buffer
	prev := make([]byte, blockSize)
	copy(prev, iv) // copy to avoid mutating caller's iv

	tmp := make([]byte, blockSize)
	for i := 0; i < len(ciphertext); i += blockSize {
		cblock := ciphertext[i : i+blockSize]

		block.Decrypt(tmp, cblock)

		pblock, err := ch2.Buf2XOR(tmp, prev)
		if err != nil {
			return nil, fmt.Errorf("Error occured when xor against previous %s", err)
		}

		// append plaintext bytes
		if _, err := plaintext.Write(pblock); err != nil {
			return nil, fmt.Errorf("append plaintext failed: %w", err)
		}

		copy(prev, cblock)

	}

	unpadded, err := pkcs7Unpad(plaintext.Bytes(), blockSize)
	if err != nil {
		return nil, fmt.Errorf("Error unpadding blocks %w", err)
	}
	return unpadded, nil
}

// pkcs7Unpad removes PKCS#7 padding and validates it.
// returns error if padding is invalid.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("invalid padding length")
	}
	// verify padding bytes
	for i := 0; i < pad; i++ {
		if data[len(data)-1-i] != byte(pad) {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-pad], nil
}
