package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// NewAESGCM creates a new AES-GCM cipher instance from a 32-byte key.
func NewAESGCM(key *[KeySize]byte) (cipher.AEAD, error) {
	// Create a new AES cipher block from the key. AES-256 is used because our key is 32 bytes.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("could not create new aes cipher: %w", err)
	}

	// Wrap the AES block in GCM mode.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create new gcm cipher: %w", err)
	}

	return aead, nil
}
