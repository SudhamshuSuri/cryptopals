package ch6

import (
	"fmt"
	"sort"
)

// KeySizeScore holds a key size and its corresponding average normalized Hamming distance.
type KeySizeScore struct {
	KeySize int
	Score   float64
}

// FindKeySize analyzes the ciphertext to determine the most probable key size.
func FindKeySize(buf []byte, minKeySize, maxKeySize, numBlocks int) ([]KeySizeScore, error) {
	var scores []KeySizeScore

	for keySize := minKeySize; keySize <= maxKeySize; keySize++ {
		var distances []float64
		totalBlocks := numBlocks

		// Ensure there is enough data for the specified number of blocks
		if len(buf) < keySize*(totalBlocks+1) {
			totalBlocks = (len(buf) / keySize) - 1
		}

		if totalBlocks < 1 {
			continue
		}

		for i := range totalBlocks {
			start1 := i * keySize
			start2 := (i + 1) * keySize

			block1 := buf[start1 : start1+keySize]
			block2 := buf[start2 : start2+keySize]

			dist, err := HammingDistance(block1, block2)
			if err != nil {
				return nil, err
			}

			normalized := float64(dist) / float64(keySize)
			distances = append(distances, normalized)
		}

		// Calculate the average normalized distance
		var sum float64
		for _, d := range distances {
			sum += d
		}
		avg := sum / float64(len(distances))

		scores = append(scores, KeySizeScore{KeySize: keySize, Score: avg})
	}

	// Sort the scores by ascending average normalized distance
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score < scores[j].Score
	})

	return scores, nil
}

type KeySizeSrtuct struct {
	KeySize int
	score   float64
}

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("inputs must be of equal length")
	}

	distance := 0
	for i := range a {
		xor := a[i] ^ b[i]
		for xor != 0 {
			distance++
			xor &= xor - 1
		}
	}
	return distance, nil
}
