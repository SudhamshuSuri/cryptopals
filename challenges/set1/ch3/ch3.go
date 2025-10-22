package ch3

import (
	"unicode"
)

func singleByteXOR(input []byte, key byte) []byte {
	result := make([]byte, len(input))
	for i := range input {
		result[i] = input[i] ^ key
	}
	return result
}

func FindBestDecryption(ciphertext []byte) (bestPlaintext []byte, bestKey byte, bestScore float64) {
	bestScore = -1
	for key := 0; key < 256; key++ {
		plaintext := singleByteXOR(ciphertext, byte(key))
		score := scoreText(plaintext)
		if score > bestScore {
			bestScore = score
			bestPlaintext = plaintext
			bestKey = byte(key)
		}
	}
	return
}
func scoreText(text []byte) float64 {
	frequencies := map[byte]float64{
		'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253,
		'e': 12.702, 'f': 2.228, 'g': 2.015, 'h': 6.094,
		'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
		'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929,
		'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
		'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
		'y': 1.974, 'z': 0.074, ' ': 13.000,
	}

	var score float64
	for _, b := range text {
		if freq, ok := frequencies[byte(unicode.ToLower(rune(b)))]; ok {
			score += freq
		}
	}
	return score
}
