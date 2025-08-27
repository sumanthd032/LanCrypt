package transfer

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"

	"github.com/sumanthd032/lancrypt/pkg/crypto" 
	"golang.org/x/crypto/curve25519"
)

// Sender represents the state for the sending side of the file transfer.
type Sender struct {
	FilePath     string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte
	listener     net.Listener
}

// ... (NewSender function remains the same) ...
func NewSender(filePath string) (*Sender, error) {
	// ... (no changes in this function)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", filePath)
		}
		return nil, fmt.Errorf("could not access file: %w", err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file: %s", filePath)
	}

	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("could not start listener: %w", err)
	}

	s := &Sender{
		FilePath:   filePath,
		privateKey: privateKey,
		publicKey:  publicKey,
		listener:   listener,
	}

	return s, nil
}


// Start begins the sender's process of listening for a connection.
func (s *Sender) Start() error {
	addr := s.listener.Addr().String()
	fmt.Printf("✅ Sender is ready.\n")
	fmt.Printf("Waiting for receiver on: %s\n", addr)
	fmt.Printf("Use this address as the code for the receiver.\n\n")

	conn, err := s.listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept connection: %w", err)
	}
	defer conn.Close()
	s.listener.Close()

	fmt.Printf("🤝 Peer connected from: %s\n", conn.RemoteAddr())

	// Perform the key exchange.
	fmt.Println("Performing secure key exchange...")
	sharedSecret, err := crypto.PerformKeyExchange(conn, &s.privateKey, &s.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}
	s.sharedSecret = sharedSecret
	fmt.Printf("✅ Key exchange successful. Shared secret established.\n")
	// We can print the key for debugging. NEVER do this in a real application.
	// fmt.Printf("DEBUG: Shared Secret: %x\n", *s.sharedSecret)

	// TODO: Start encrypted file transfer.
	fmt.Println("Session finished.")

	return nil
}

func (s *Sender) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}
