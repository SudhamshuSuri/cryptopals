package ch7

import (
	"fmt"
	"crypto/aes"
)

func ReadAESEncryption( ciphertext, key []byte ) ([]byte, error){
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0{
		fmt.Errorf("Cipher text not a multiple of block size")
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	bs := block.BlockSize()
	for start := 0; start < len(ciphertext); start += bs {
		block.Decrypt(plaintext[start:start+bs], ciphertext[start:start+bs])
	}
	return plaintext, nil
}
