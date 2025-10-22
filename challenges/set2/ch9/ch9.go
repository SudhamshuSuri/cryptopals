// ch9/pad.go (or appropriate file)
package ch9

import (
	"bytes"
	"fmt"
)

// PKCSPadding pads data to a multiple of blockSize according to PKCS#7.
// It returns the padded data (and never an error for reasonable blockSize).
func PKCSPadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size %d", blockSize)
	}

	// number of bytes to add (1..blockSize)
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		// if already aligned, add a full block of padding
		padLen = blockSize
	}

	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...), nil
}

// PKCS7Unpad removes PKCS#7 padding and validates it.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size %d", blockSize)
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("invalid padding length")
	}

	// verify all padding bytes are correct
	for i := 0; i < padLen; i++ {
		if data[len(data)-1-i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-padLen], nil
}

