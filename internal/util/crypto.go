package util

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256Hex(input []byte) string {
	return hex.EncodeToString(SHA256(input))
}

func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
