package ch2

import (
	"encoding/hex"
	"testing"
)

func TestBuf2XOR(t *testing.T) {
	// Test case: Valid input
	hexStr1 := "1c0111001f010100061a024b53535009181c"
	hexStr2 := "686974207468652062756c6c277320657965"
	expectedHex := "746865206b696420646f6e277420706c6179"

	buf1, err := hex.DecodeString(hexStr1)
	if err != nil {
		t.Fatalf("Failed to decode hexStr1: %v", err)
	}

	buf2, err := hex.DecodeString(hexStr2)
	if err != nil {
		t.Fatalf("Failed to decode hexStr2: %v", err)
	}

	result, err := Buf2XOR(buf1, buf2)
	if err != nil {
		t.Fatalf("Buf2XOR returned an error: %v", err)
	}

	resultHex := hex.EncodeToString(result)
	if resultHex != expectedHex {
		t.Errorf("Expected %s, got %s", expectedHex, resultHex)
	}

	// Test case: Unequal lengths
	buf3 := []byte{0x1c, 0x01, 0x00}
	buf4 := []byte{0x68, 0x69}
	_, err = Buf2XOR(buf3, buf4)
	if err == nil {
		t.Errorf("Expected error for unequal buffer lengths, got nil")
	}
}

