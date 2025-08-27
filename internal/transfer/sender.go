package transfer

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sumanthd032/lancrypt/internal/discovery"
	"github.com/sumanthd032/lancrypt/internal/rendezvous"
	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"github.com/sumanthd032/lancrypt/pkg/util"
	"golang.org/x/crypto/curve25519"
)

type Sender struct {
	FilePath     string
	Passphrase   string
	privateKey   [32]byte
	publicKey    [32]byte
	sharedSecret *[32]byte
	listener     net.Listener
}

func NewSender(filePath, passphrase string) (*Sender, error) {
	// ... (This function remains the same as Step 9)
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
		Passphrase: passphrase,
		privateKey: privateKey,
		publicKey:  publicKey,
		listener:   listener,
	}

	return s, nil
}

func (s *Sender) Start() error {
	rvServer := rendezvous.NewServer()
	rvServer.Start()
	defer rvServer.Stop()

	addrParts := strings.Split(s.listener.Addr().String(), ":")
	port := addrParts[len(addrParts)-1]

	code, err := util.GenerateCode(3)
	if err != nil {
		return fmt.Errorf("could not generate code: %w", err)
	}

	rvServer.Register(code, port)

	rendezvousPort, _ := strconv.Atoi(rendezvous.RendezvousPort)
	mdnsServer, err := discovery.PublishService(code, rendezvousPort)
	if err != nil {
		return fmt.Errorf("could not publish mDNS service: %w", err)
	}
	defer mdnsServer.Shutdown()

	fmt.Printf("✅ Sender is ready.\nYour transfer code is: %s\n\n", code)
	fmt.Printf("On the other device, run: lancrypt recv --code %s\n", code)

	conn, err := s.listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept connection: %w", err)
	}
	defer conn.Close()
	s.listener.Close()

	fmt.Printf("\n🤝 Peer connected from: %s\n", conn.RemoteAddr())

	initialSecret, err := crypto.PerformKeyExchange(conn, &s.privateKey, &s.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	finalSecret, err := crypto.DeriveKey(initialSecret, s.Passphrase)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	s.sharedSecret = finalSecret
	fmt.Printf("✅ Key exchange successful.\n")

	sas := crypto.GenerateSAS(s.sharedSecret, 3)
	if err := promptForConfirmation(sas); err != nil {
		return err
	}

	if err := sendFile(conn, s.FilePath, s.sharedSecret); err != nil {
		return fmt.Errorf("file transfer failed: %w", err)
	}

	fmt.Println("✅ File transfer complete.")
	fmt.Println("Session finished.")
	return nil
}

func (s *Sender) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}
