package transfer

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"io"

	"github.com/sumanthd032/lancrypt/internal/discovery"
	"github.com/sumanthd032/lancrypt/pkg/crypto"
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
	// ... (This function remains the same as Step 9)
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

	if err := receiveFile(conn, r.sharedSecret); err != nil {
		return fmt.Errorf("file transfer failed: %w", err)
	}

	fmt.Println("✅ File transfer complete.")
	fmt.Println("Session finished.")
	return nil
}
