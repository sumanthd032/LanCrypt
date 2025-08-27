package util

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var words = []string{
	"apple", "banana", "carrot", "dog", "elephant", "frog", "grape", "hat", "ice",
	"jungle", "kite", "lemon", "moon", "ninja", "orange", "pencil", "queen", "robot",
	"snake", "tiger", "unicorn", "violet", "whale", "xylophone", "yacht", "zebra",
}

// GenerateCode creates a memorable, multi-word code.
func GenerateCode(numWords int) (string, error) {
	code := ""
	for i := 0; i < numWords; i++ {
		// Generate a cryptographically secure random number.
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", fmt.Errorf("could not generate random number for code: %w", err)
		}
		if i > 0 {
			code += "-"
		}
		code += words[n.Int64()]
	}
	return code, nil
}