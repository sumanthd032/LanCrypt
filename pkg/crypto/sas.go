package crypto

import (
	"crypto/sha256"
	"strings"
)

// A list of simple, unambiguous words for the SAS.
var sasWordList = []string{
	"apple", "bird", "book", "bow", "cat", "cloud", "coin", "cup", "dog", "door",
	"duck", "fan", "fish", "fox", "grape", "hat", "heart", "house", "ice", "jar",
	"key", "kite", "leaf", "lion", "moon", "mouse", "nest", "net", "orange", "pen",
	"pig", "pipe", "queen", "rain", "ring", "robot", "rock", "ship", "shoe", "star",
	"sun", "tree", "tulip", "van", "vest", "vine", "watch", "web", "wheel", "wolf",
	"yacht", "yarn", "zebra",
}

// GenerateSAS creates a human-readable Short Authentication String from a shared secret.
func GenerateSAS(sharedSecret *[KeySize]byte, numWords int) string {
	// Use SHA256 to create a deterministic digest of the shared secret.
	hash := sha256.Sum256(sharedSecret[:])

	var words []string
	wordListSize := len(sasWordList)

	// Use bytes from the hash to select words from the list.
	for i := 0; i < numWords; i++ {
		// Ensure we don't go out of bounds of our hash array.
		if i >= len(hash) {
			break
		}
		wordIndex := int(hash[i]) % wordListSize
		words = append(words, sasWordList[wordIndex])
	}

	return strings.Join(words, "-")
}
