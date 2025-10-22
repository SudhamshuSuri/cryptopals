package ch4

import (
	"bufio"
	"encoding/hex"
	"log"
	"os"

	ch3 "cryptopals/challenges/set1/ch3"
)

func ProcessFile(filepath string) (int, byte, []byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	lineNumber := 0
	var bestScore float64
	var bestPlainText []byte
	var bestKey byte
	var bestLineNumber int

	for scanner.Scan() {
		lineNumber++
		hexline := scanner.Text()
		ciphertext, err := hex.DecodeString(hexline)
		if err != nil {
			log.Fatalf("Error decoding string: %v", err)
		}
		plaintext, key, score := ch3.FindBestDecryption(ciphertext)
		if score > bestScore {
			bestScore = score
			bestLineNumber = lineNumber
			bestKey = key
			bestPlainText = plaintext
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	return bestLineNumber, bestKey, bestPlainText, nil
}
