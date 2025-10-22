package ch5

func RotateXOREncoding(buf []byte) ([]byte, error) {
	key := []byte("ICE")
	retstr := make([]byte, len(buf))
	for idx := range buf {
		retstr[idx] = buf[idx] ^ key[idx%len(key)]
	}
	return retstr, nil
}
