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

	"github.com/sumanthd032/lancrypt/internal/discovery"
	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"github.com/sumanthd032/lancrypt/pkg/util"
	"golang.org/x/crypto/curve25519"
)

type Receiver struct {
	Code         string
	Passphrase   string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte
}

func NewReceiver(code, passphrase string) (*Receiver, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	r := &Receiver{
		Code:       code,
		Passphrase: passphrase,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return r, nil
}

func (r *Receiver) Connect() error {
	fmt.Printf("🔎 Searching for sender '%s' on the local network...\n", r.Code)
	entry, err := discovery.DiscoverService(r.Code)
	if err != nil {
		return err
	}
	host := entry.AddrIPv4[0].String()
	fmt.Printf("✅ Found sender at %s\n", host)

	fmt.Printf("Resolving code '%s' via host %s...\n", r.Code, host)
	rendezvousURL := fmt.Sprintf("http://%s:%d/%s", host, entry.Port, r.Code)

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

	targetAddr := net.JoinHostPort(host, port)
	fmt.Printf("✅ Code resolved. Connecting to sender at %s\n", targetAddr)

	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("could not connect to sender: %w", err)
	}
	defer conn.Close()

	fmt.Printf("✅ Connected to sender: %s\n", conn.RemoteAddr())

	fmt.Println("Performing secure key exchange...")
	initialSecret, err := crypto.PerformKeyExchange(conn, &r.privateKey, &r.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	finalSecret, err := crypto.DeriveKey(initialSecret, r.Passphrase)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	r.sharedSecret = finalSecret
	fmt.Printf("✅ Key exchange successful.\n")

	sas := crypto.GenerateSAS(r.sharedSecret, 3)
	if err := promptForConfirmation(sas); err != nil {
		return err
	}

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

	bar := util.NewProgressBar(meta.Size, fmt.Sprintf("Receiving %s", meta.Name))

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

		bytesWritten, err := file.Write(decryptedChunk)
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		chunkIndex++
		bar.Add(bytesWritten)
	}

	bar.Finish()
	fmt.Println("✅ File transfer complete.")
	fmt.Println("Session finished.")
	return nil
}
