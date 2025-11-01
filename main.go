package main

import (
	"fmt"
	"log"
	"bytes"

	ch12 "cryptopals/challenges/set2/ch12"
)

func repeat(b byte, n int) []byte {
	if n <= 0 {
		return []byte{}
	}

	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func detectBlockSize(oracle func([]byte) ([]byte, error)) (int, error) {
	prevLen := -1
	for n := 1; n <= 128; n++ {
		in := repeat('A', n)
		ct, err := oracle(in)
		if err != nil {
			return 0, fmt.Errorf("Oracle error: %w", err)
		}
		if prevLen != -1 {
			if len(ct) > prevLen {
				return len(ct) - prevLen, nil
			}
		}
		prevLen = len(ct)
	}
	return 0, fmt.Errorf("Could not detect block size")
}


func isECB(oracle func([]byte) ([]byte, error) ,blockSize int) (bool, error){
	in := repeat('A', blockSize*3)
	ct, err := oracle(in)
	if err != nil{
		return false, err
	}
	
	seen := make(map[string]bool)
	for i:=0; i+blockSize < len(ct); i++{
		b := string(ct[i: i+blockSize])
		if seen[b] {
			return true, nil
		}
		seen[b] = true
	}

	return false, nil
} 


func blockAt(ct []byte, blockSize, blockIndex int) ([]byte, error) {
	start := blockSize * blockIndex
	if start + blockSize > len(ct){
		return nil, fmt.Errorf("Block index out of range")
	}
	return ct[start : start+blockSize], nil
}

// recoverSecret does the byte-at-a-time recovery against the oracle.
// It returns the recovered secret bytes (no assumption about length).
func recoverSecret(oracle func([]byte) ([]byte, error), blockSize int) ([]byte, error) {
	recovered := make([]byte, 0)

	// find total ciphertext length for empty input so we know an upper bound
	ct0, err := oracle([]byte{})
	if err != nil {
		return nil, err
	}
	totalLen := len(ct0)

	// Iterate over byte positions until we fail to match (end of secret/padding)
	for i := 0; i < totalLen; i++ {
		blockIndex := i / blockSize
		offsetInBlock := i % blockSize

		// Number of prefix bytes to align unknown byte to the last byte of a block
		padLen := blockSize - 1 - offsetInBlock
		pad := repeat('A', padLen)

		// Get the ciphertext block that contains the unknown byte
		ct, err := oracle(pad)
		if err != nil {
			return nil, fmt.Errorf("oracle error: %w", err)
		}
		targetBlock, err := blockAt(ct, blockSize, blockIndex)
		if err != nil {
			// If the target block is out of range, we probably reached the end
			return recovered, nil
		}

		// Build dictionary: map ciphertext block -> candidate byte
		dict := make(map[string]byte, 256)
		for b := 0; b < 256; b++ {
			// candidate input = pad + recovered + candidateByte
			candidateInput := append(append([]byte{}, pad...), recovered...)
			candidateInput = append(candidateInput, byte(b))

			candCt, err := oracle(candidateInput)
			if err != nil {
				return nil, fmt.Errorf("oracle error while building dict: %w", err)
			}
			candBlock, err := blockAt(candCt, blockSize, blockIndex)
			if err != nil {
				// shouldn't happen normally; skip
				continue
			}
			dict[string(candBlock)] = byte(b)
		}

		// Lookup the target block in the dictionary
		if val, ok := dict[string(targetBlock)]; ok {
			recovered = append(recovered, val)
			// continue to next byte
			continue
		}

		// No match means we've likely reached padding / end of secret
		break
	}

	// Trim any PKCS#7 padding if present (optional; the secret often is raw bytes)
	// If you want to return raw bytes exactly as discovered, skip unpadding here.
	return recovered, nil
}


func main(){
	oracle := func(in []byte) ([]byte, error) {
		return ch12.ECBOracle(in)
	}

	bs, err := detectBlockSize(oracle)
	if err != nil {
		log.Fatalf("Block size detection failed %v", err)
	}

	ok, err := isECB(oracle, bs)
		if err != nil {
			log.Fatalf("Error detecting ECB %v", err)
		}

	if !ok{
		log.Fatalf("oracle does not appear to be ECB")
	}

	fmt.Println("Confirmed ECB mode")

	secret, err := recoverSecret(oracle, bs)
	if err != nil {
		log.Fatalf("Error recovering secret %v", err)
	}
	fmt.Printf("Recovered %d bytes:\n%s\n", len(secret), string(bytes.TrimRight(secret, "\x00")))
}
