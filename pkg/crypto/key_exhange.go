// Package crypto provides cryptographic helper functions for LanCrypt.
package crypto

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/curve25519"
)

const KeySize = 32 // Defines the size of our keys (32 bytes / 256 bits)

// PerformKeyExchange handles the cryptographic handshake over a network connection.
// It sends the local public key, receives the remote public key, and computes the shared secret.
func PerformKeyExchange(conn net.Conn, localPrivateKey, localPublicKey *[KeySize]byte) (*[KeySize]byte, error) {
	// --- Step 1: Send our public key ---
	// We write our public key to the connection for the other peer to receive.
	if _, err := conn.Write(localPublicKey[:]); err != nil {
		return nil, fmt.Errorf("failed to send public key: %w", err)
	}

	// --- Step 2: Receive the peer's public key ---
	// We read exactly KeySize bytes from the connection to get the peer's public key.
	remotePublicKey := new([KeySize]byte)
	if _, err := io.ReadFull(conn, remotePublicKey[:]); err != nil {
		return nil, fmt.Errorf("failed to receive public key: %w", err)
	}

	// --- Step 3: Compute the shared secret ---
	// This is the core of the ECDH algorithm. We combine our private key
	// with the peer's public key to derive the shared secret.
	sharedSecret, err := curve25519.X25519(localPrivateKey[:], remotePublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("could not compute shared secret: %w", err)
	}

	// Convert the resulting byte slice into a 32-byte array.
	sharedSecretArray := new([KeySize]byte)
	copy(sharedSecretArray[:], sharedSecret)

	return sharedSecretArray, nil
}
