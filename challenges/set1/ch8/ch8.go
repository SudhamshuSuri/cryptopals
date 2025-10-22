package ch8

import (
	"bufio"
	"fmt"
	"os"
	"encoding/hex"
)


func countDuplicateBlocks(ciphertext []byte, blocksize int) (int){
	countmap := make(map[string] int)
	duplicates := 0

	if blocksize <= 0{
		return 0
	}
	
	for i := 0; i < len(ciphertext); i+= blocksize{
		block := ciphertext[i : i + blocksize]
		key := string(block)
		prev := countmap[key]
		countmap[key] = prev + 1 
		if prev >= 1 {
			duplicates ++ 
		}
	}
	return duplicates

}	 

func DetectECBCipher(fileName string, blocksize int) (bestLine, bestCipher []byte, err error) {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Errorf("Error opening file ")
		return nil, nil, err
	}
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	maxRepeats := 0

	for scanner.Scan(){
		lineNum++
		hexLine := scanner.Text()
		ciphertext, err := hex.DecodeString(hexLine)
		if err != nil {
			fmt.Errorf("Error decoding string ")
			continue
		}

		repeats := countDuplicateBlocks(ciphertext, blocksize)
		if repeats > maxRepeats{
			maxRepeats = repeats
			bestCipher = ciphertext
			bestLine = []byte(hexLine)
		}

	}
	if err = scanner.Err(); err != nil { return nil, nil, err}
	return bestLine, bestCipher, nil
}

