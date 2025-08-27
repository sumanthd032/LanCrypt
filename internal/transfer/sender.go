package transfer

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/curve25519"
)

// Sender represents the state for the sending side of the file transfer.
type Sender struct {
	FilePath    string
	privateKey  [32]byte
	publicKey   [32]byte
	listener    net.Listener
	// We will add more fields here in later steps, like the shared secret key.
}

// NewSender creates and initializes a new Sender instance.
func NewSender(filePath string) (*Sender, error) {
	// 1. Validate the input file path.
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		// os.IsNotExist is a reliable way to check if the error is because the file doesn't exist.
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", filePath)
		}
		return nil, fmt.Errorf("could not access file: %w", err)
	}

	// Make sure the path points to a regular file, not a directory.
	if fileInfo.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file: %s", filePath)
	}

	// 2. Generate the ephemeral key pair for the session.
	// The private key is a random 32-byte array.
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	// The public key is derived from the private key using the Curve25519 algorithm.
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// 3. Start a TCP listener on a random available port.
	// Using port "0" is a standard way to ask the OS to assign a free port.
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("could not start listener: %w", err)
	}

	// Create the Sender struct with the initialized values.
	s := &Sender{
		FilePath:    filePath,
		privateKey:  privateKey,
		publicKey:   publicKey,
		listener:    listener,
	}

	return s, nil
}

// Start begins the sender's process of listening for a connection.
// This function will block until a connection is made or an error occurs.
func (s *Sender) Start() error {
	// Get the address and port we are listening on.
	addr := s.listener.Addr().String()
	fmt.Printf("✅ Sender is ready.\n")
	fmt.Printf("Waiting for receiver on: %s\n", addr)
	
    // We will generate a user-friendly code in the next step. For now, this is our "code".
	fmt.Printf("Use this address as the code for the receiver.\n\n")

	// 4. Wait for and accept a single incoming connection.
	// The Accept() call will block here until a client (the receiver) connects.
	conn, err := s.listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept connection: %w", err)
	}
	
    // Once a connection is accepted, we close the listener to prevent anyone else from connecting.
    // This enforces our one-time-use session rule.
	s.listener.Close()

	fmt.Printf("🤝 Peer connected from: %s\n", conn.RemoteAddr())

	// TODO: In the next step, we will perform the key exchange and start the transfer.
	// For now, we just close the connection.
	conn.Close()
	fmt.Println("Session finished.")

	return nil
}

// Close cleans up the sender's resources, primarily the network listener.
func (s *Sender) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}
