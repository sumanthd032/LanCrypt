package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/sumanthd032/lancrypt/internal/rendezvous"
	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

// Receiver represents the state for the receiving side of the file transfer.
type Receiver struct {
	Code         string
	Host         string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte
}

// NewReceiver creates and initializes a new Receiver instance.
func NewReceiver(code, host string) (*Receiver, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	r := &Receiver{
		Code:       code,
		Host:       host,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return r, nil
}

// Connect attempts to establish a connection with the sender.
func (r *Receiver) Connect() error {
	// 1. Resolve the code to a port via the rendezvous server
	fmt.Printf("Resolving code '%s' via host %s...\n", r.Code, r.Host)
	rendezvousURL := fmt.Sprintf("http://%s:%s/%s", r.Host, rendezvous.RendezvousPort, r.Code)

	resp, err := http.Get(rendezvousURL)
	if err != nil {
		return fmt.Errorf("could not contact rendezvous server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rendezvous server returned an error (code not found or server issue)")
	}

	portBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read port from rendezvous response: %w", err)
	}
	port := string(portBytes)

	// The actual address for the file transfer
	targetAddr := net.JoinHostPort(r.Host, port)
	fmt.Printf("✅ Code resolved. Connecting to sender at %s\n", targetAddr)

	// 2. Connect to the resolved address
	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("could not connect to sender: %w", err)
	}
	defer conn.Close()

	fmt.Printf("✅ Connected to sender: %s\n", conn.RemoteAddr())

	// Key Exchange
	fmt.Println("Performing secure key exchange...")
	sharedSecret, err := crypto.PerformKeyExchange(conn, &r.privateKey, &r.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}
	r.sharedSecret = sharedSecret
	fmt.Printf("✅ Key exchange successful.\n")

	// Receive File Metadata
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

	// Receive, Decrypt, and Write File
	fmt.Println("Receiving and decrypting file...")
	file, err := os.Create(meta.Name)
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

		if chunkSize == 0 {
			break
		}

		encryptedChunk := make([]byte, chunkSize)
		if _, err := io.ReadFull(conn, encryptedChunk); err != nil {
			return fmt.Errorf("could not read chunk: %w", err)
		}

		binary.LittleEndian.PutUint64(nonce, chunkIndex)

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