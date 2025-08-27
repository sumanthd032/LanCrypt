package transfer

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

// Receiver represents the state for the receiving side of the file transfer.
type Receiver struct {
	Code         string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte // <-- ADD THIS FIELD
}

// ... (NewReceiver function remains the same) ...
func NewReceiver(code string) (*Receiver, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	r := &Receiver{
		Code:       code,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return r, nil
}

// Connect attempts to establish a connection with the sender and perform key exchange.
func (r *Receiver) Connect() error {
	fmt.Printf("Attempting to connect to sender with code: %s\n", r.Code)

	conn, err := net.Dial("tcp", r.Code)
	if err != nil {
		return fmt.Errorf("could not connect to sender: %w", err)
	}
	defer conn.Close()

	fmt.Printf("✅ Connected to sender: %s\n", conn.RemoteAddr())

	// Perform the key exchange.
	fmt.Println("Performing secure key exchange...")
	sharedSecret, err := crypto.PerformKeyExchange(conn, &r.privateKey, &r.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}
	r.sharedSecret = sharedSecret
	fmt.Printf("✅ Key exchange successful. Shared secret established.\n")
	// We can print the key for debugging. NEVER do this in a real application.
	// fmt.Printf("DEBUG: Shared Secret: %x\n", *r.sharedSecret)

	// TODO: Start encrypted file transfer.
	fmt.Println("Session finished.")

	return nil
}