package transfer

import (
	"crypto/rand"
	"fmt"
	"net"

	"golang.org/x/crypto/curve25519"
)

// Receiver represents the state for the receiving side of the file transfer.
type Receiver struct {
	Code        string
	privateKey  [32]byte
	publicKey   [32]byte
	// We will add more fields here, like the connection and shared secret key.
}

// NewReceiver creates and initializes a new Receiver instance.
func NewReceiver(code string) (*Receiver, error) {
	// 1. Generate the ephemeral key pair for the session.
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Create the Receiver struct with the initialized values.
	r := &Receiver{
		Code:       code,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return r, nil
}

// Connect attempts to establish a connection with the sender.
func (r *Receiver) Connect() error {
	fmt.Printf("Attempting to connect to sender with code: %s\n", r.Code)

	// 2. Dial the sender's address.
	// net.Dial is the function used by a client to initiate a connection.
	conn, err := net.Dial("tcp", r.Code)
	if err != nil {
		return fmt.Errorf("could not connect to sender: %w", err)
	}

	fmt.Printf("✅ Connected to sender: %s\n", conn.RemoteAddr())

	// TODO: In the next step, we will perform the key exchange.
	// For now, we just close the connection.
	defer conn.Close()
	fmt.Println("Session finished.")

	return nil
}
