package main

import (
	"fmt"
	"log"

	ch11 "cryptopals/challenges/set2/ch11"
)

// isECB checks whether ciphertext likely came from ECB by looking for repeated blocks.
func isECB(ciphertext []byte, blockSize int) bool {
	if blockSize <= 0 {
		return false
	}
	seen := make(map[string]int)
	for i := 0; i+blockSize <= len(ciphertext); i += blockSize {
		block := ciphertext[i : i+blockSize]
		key := string(block) // binary-safe map key
		seen[key]++
		if seen[key] > 1 {
			// As soon as we see a repetition, strongly suspect ECB.
			return true
		}
	}
	return false
}

func main() {
	trials := 100
	correct := 0

	// Plaintext with repeated blocks -> makes ECB detectable
	plain := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 64 As

	for i := 0; i < trials; i++ {
		ct, _, _, modeIsECB, err := ch11.EncryptionOracle(plain)
		if err != nil {
			log.Fatalf("oracle error: %v", err)
		}

		detectedECB := isECB(ct, 16)
		if detectedECB == modeIsECB {
			correct++
		}

		// Print a short per-trial line (you can comment this out if noisy)
		fmt.Printf("trial %3d: actual=%s detected=%v\n", i+1, func() string {
			if modeIsECB {
				return "ECB"
			}
			return "CBC"
		}(), detectedECB)
	}

	fmt.Printf("\nDetected correctly %d/%d times (%.1f%%)\n", correct, trials, float64(correct)/float64(trials)*100)
}

