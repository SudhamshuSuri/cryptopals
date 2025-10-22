package ch1

import (
	"encoding/base64"
	"encoding/hex"
)

func ConvertToBase64(hexString string) (string, error) {
	// Decode hex string to bytes
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}
	// Encode bytes to base64 string
	return base64.StdEncoding.EncodeToString(bytes), nil
}
