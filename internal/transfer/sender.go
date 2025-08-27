package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

// ... (Sender struct and NewSender function remain the same) ...
type Sender struct {
	FilePath     string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte
	listener     net.Listener
}

func NewSender(filePath string) (*Sender, error) {
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


// Start is updated to handle the full transfer protocol.
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

	// 1. Key Exchange
	fmt.Println("Performing secure key exchange...")
	sharedSecret, err := crypto.PerformKeyExchange(conn, &s.privateKey, &s.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}
	s.sharedSecret = sharedSecret
	fmt.Printf("✅ Key exchange successful.\n")

	// 2. Send File Metadata
	fmt.Println("Sending file metadata...")
	file, err := os.Open(s.FilePath)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	meta := fileMetadata{
		Name: filepath.Base(s.FilePath), // Send only the filename, not the full path
		Size: fileInfo.Size(),
	}

	metaBytes, _ := json.Marshal(meta)
	// We send the size of the metadata first, so the receiver knows how much to read.
	if err := binary.Write(conn, binary.LittleEndian, uint32(len(metaBytes))); err != nil {
		return fmt.Errorf("could not send metadata size: %w", err)
	}
	if _, err := conn.Write(metaBytes); err != nil {
		return fmt.Errorf("could not send metadata: %w", err)
	}
	fmt.Printf("Sent metadata: %+v\n", meta)

	// 3. Encrypt and Stream File
	fmt.Println("Encrypting and sending file...")
	aead, err := crypto.NewAESGCM(s.sharedSecret)
	if err != nil {
		return fmt.Errorf("could not create cipher: %w", err)
	}

	chunkBuffer := make([]byte, 4*1024) // 4KB chunks
	nonce := make([]byte, aead.NonceSize())
	var chunkIndex uint64 = 0

	for {
		bytesRead, err := file.Read(chunkBuffer)
		if err == io.EOF {
			break // End of file
		}
		if err != nil {
			return fmt.Errorf("could not read file chunk: %w", err)
		}

		// Use the chunk index as the nonce (ensures it's unique for each chunk).
		binary.LittleEndian.PutUint64(nonce, chunkIndex)

		// Encrypt the chunk. The result includes the ciphertext and the auth tag.
		encryptedChunk := aead.Seal(nil, nonce, chunkBuffer[:bytesRead], nil)

		// Send the size of the encrypted chunk first.
		if err := binary.Write(conn, binary.LittleEndian, uint32(len(encryptedChunk))); err != nil {
			return fmt.Errorf("could not send chunk size: %w", err)
		}
		// Send the encrypted chunk itself.
		if _, err := conn.Write(encryptedChunk); err != nil {
			return fmt.Errorf("could not send chunk: %w", err)
		}
		chunkIndex++
	}

	// Send a zero-length chunk to signal the end of the transfer.
	if err := binary.Write(conn, binary.LittleEndian, uint32(0)); err != nil {
		return fmt.Errorf("could not send EOF signal: %w", err)
	}

	fmt.Println("\n✅ File transfer complete.")
	fmt.Println("Session finished.")
	return nil
}

// ... (Close function remains the same) ...
func (s *Sender) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}

