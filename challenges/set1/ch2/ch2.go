package ch2

import "fmt"

func Buf2XOR(buf1, buf2 []byte) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return nil, fmt.Errorf(" Input slices must have the same length ")
	}
	result := make([]byte, len(buf1))
	for i := range buf1 {
		result[i] = buf1[i] ^ buf2[i]
	}
	return result, nil
}
