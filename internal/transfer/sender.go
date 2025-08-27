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
	"strconv"
	"strings"

	"github.com/sumanthd032/lancrypt/internal/discovery"
	"github.com/sumanthd032/lancrypt/internal/rendezvous"
	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"github.com/sumanthd032/lancrypt/pkg/util"
	"golang.org/x/crypto/curve25519"
)

type fileMetadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}
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

	fmt.Printf("✅ Sender is ready.\n")
	fmt.Printf("Your transfer code is: %s\n\n", code)
	fmt.Println("The receiver can now find you automatically.")
	fmt.Printf("On the other device, run: lancrypt recv --code %s\n", code)

	conn, err := s.listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept connection: %w", err)
	}
	defer conn.Close()
	s.listener.Close()

	fmt.Printf("\n🤝 Peer connected from: %s\n", conn.RemoteAddr())

	fmt.Println("Performing secure key exchange...")
	sharedSecret, err := crypto.PerformKeyExchange(conn, &s.privateKey, &s.publicKey)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}
	s.sharedSecret = sharedSecret
	fmt.Printf("✅ Key exchange successful.\n")

	fmt.Println("Sending file metadata...")
	file, err := os.Open(s.FilePath)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	meta := fileMetadata{
		Name: filepath.Base(s.FilePath),
		Size: fileInfo.Size(),
	}

	metaBytes, _ := json.Marshal(meta)
	if err := binary.Write(conn, binary.LittleEndian, uint32(len(metaBytes))); err != nil {
		return fmt.Errorf("could not send metadata size: %w", err)
	}
	if _, err := conn.Write(metaBytes); err != nil {
		return fmt.Errorf("could not send metadata: %w", err)
	}
	fmt.Printf("Sent metadata: %+v\n", meta)

	fmt.Println("Encrypting and sending file...")
	aead, err := crypto.NewAESGCM(s.sharedSecret)
	if err != nil {
		return fmt.Errorf("could not create cipher: %w", err)
	}

	chunkBuffer := make([]byte, 4*1024)
	nonce := make([]byte, aead.NonceSize())
	var chunkIndex uint64 = 0

	for {
		bytesRead, err := file.Read(chunkBuffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read file chunk: %w", err)
		}

		binary.LittleEndian.PutUint64(nonce, chunkIndex)
		encryptedChunk := aead.Seal(nil, nonce, chunkBuffer[:bytesRead], nil)

		if err := binary.Write(conn, binary.LittleEndian, uint32(len(encryptedChunk))); err != nil {
			return fmt.Errorf("could not send chunk size: %w", err)
		}
		if _, err := conn.Write(encryptedChunk); err != nil {
			return fmt.Errorf("could not send chunk: %w", err)
		}
		chunkIndex++
	}

	if err := binary.Write(conn, binary.LittleEndian, uint32(0)); err != nil {
		return fmt.Errorf("could not send EOF signal: %w", err)
	}

	fmt.Println("\n✅ File transfer complete.")
	fmt.Println("Session finished.")
	return nil
}

func (s *Sender) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}
