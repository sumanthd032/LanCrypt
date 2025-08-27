package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey uses HKDF to derive a strong cryptographic key from an initial shared secret and an optional passphrase.
func DeriveKey(secret *[KeySize]byte, passphrase string) (*[KeySize]byte, error) {
	// HKDF is a two-step process: Extract and Expand.
	// We use the passphrase as the "salt" which adds entropy. If no passphrase is provided, salt is nil.
	var salt []byte
	if passphrase != "" {
		salt = []byte(passphrase)
	}

	// 1. Extract: Create a pseudorandom key from the initial secret and salt.
	// This step concentrates the entropy of the input keying material.
	hash := sha256.New
	extractor := hkdf.New(hash, secret[:], salt, nil)

	// 2. Expand: Generate the final key of the desired length.
	finalKey := new([KeySize]byte)
	_, err := io.ReadFull(extractor, finalKey[:])
	if err != nil {
		return nil, err
	}

	return finalKey, nil
}
