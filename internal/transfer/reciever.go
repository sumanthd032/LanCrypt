package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

// We need the metadata struct here too.
type fileMetadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// ... (Receiver struct and NewReceiver function remain the same) ...
type Receiver struct {
	Code         string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte
}

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


// Connect is updated to handle the full transfer protocol.
func (r *Receiver) Connect() error {
	fmt.Printf("Attempting to connect to sender with code: %s\n", r.Code)

	conn, err := net.Dial("tcp", r.Code)
	if err != nil {
		return fmt.Errorf("could not connect to sender: %w", err)
	}
	defer conn.Close()

	fmt.Printf("✅ Connected to sender: %s\n", conn.RemoteAddr())

	// 1. Key Exchange
	fmt.Println("Performing secure key exchange...")
	sharedSecret, err := crypto.PerformKeyExchange(conn, &r.privateKey, &r.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}
	r.sharedSecret = sharedSecret
	fmt.Printf("✅ Key exchange successful.\n")

	// 2. Receive File Metadata
	fmt.Println("Receiving file metadata...")
	var metaSize uint32
	if err := binary.Read(conn, binary.LittleEndian, &metaSize); err != nil {
		return fmt.Errorf("could not read metadata size: %w", err)
	}

	metaBytes := make([]byte, metaSize)
	if _, err := io.ReadFull(conn, metaBytes); err != nil {
		return fmt.Errorf("could not read metadata: %w", err)
	}

	var meta fileMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return fmt.Errorf("could not decode metadata: %w", err)
	}
	fmt.Printf("Received metadata: %+v\n", meta)

	// 3. Receive, Decrypt, and Write File
	fmt.Println("Receiving and decrypting file...")
	file, err := os.Create(meta.Name) // Create the output file
	if err != nil {
		return fmt.Errorf("could not create file: %w", err)
	}
	defer file.Close()

	aead, err := crypto.NewAESGCM(r.sharedSecret)
	if err != nil {
		return fmt.Errorf("could not create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	var chunkIndex uint64 = 0

	for {
		var chunkSize uint32
		if err := binary.Read(conn, binary.LittleEndian, &chunkSize); err != nil {
			return fmt.Errorf("could not read chunk size: %w", err)
		}

		// The sender signals EOF by sending a chunk size of 0.
		if chunkSize == 0 {
			break
		}

		encryptedChunk := make([]byte, chunkSize)
		if _, err := io.ReadFull(conn, encryptedChunk); err != nil {
			return fmt.Errorf("could not read chunk: %w", err)
		}

		// Use the same chunk index as the sender to generate the nonce.
		binary.LittleEndian.PutUint64(nonce, chunkIndex)

		// Decrypt the chunk. If the data was tampered with, this will fail.
		decryptedChunk, err := aead.Open(nil, nonce, encryptedChunk, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk #%d: %w", chunkIndex, err)
		}

		if _, err := file.Write(decryptedChunk); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		chunkIndex++
	}

	fmt.Println("\n✅ File transfer complete.")
	fmt.Println("Session finished.")
	return nil
}
