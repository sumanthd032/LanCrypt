package transfer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/sumanthd032/lancrypt/pkg/crypto"
	"github.com/sumanthd032/lancrypt/pkg/util"
)

// fileMetadata holds information about the file being transferred.
type fileMetadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// sendFile handles the logic for sending the file's content after a secure connection is established.
func sendFile(conn net.Conn, filePath string, sharedSecret *[32]byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	meta := fileMetadata{
		Name: filepath.Base(filePath),
		Size: fileInfo.Size(),
	}

	metaBytes, _ := json.Marshal(meta)
	if err := binary.Write(conn, binary.LittleEndian, uint32(len(metaBytes))); err != nil {
		return fmt.Errorf("could not send metadata size: %w", err)
	}
	if _, err := conn.Write(metaBytes); err != nil {
		return fmt.Errorf("could not send metadata: %w", err)
	}

	bar := util.NewProgressBar(meta.Size, fmt.Sprintf("Sending %s", meta.Name))
	defer bar.Finish()

	aead, err := crypto.NewAESGCM(sharedSecret)
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
		bar.Add(bytesRead)
	}

	return binary.Write(conn, binary.LittleEndian, uint32(0)) // Send EOF signal
}

// receiveFile handles the logic for receiving a file's content.
func receiveFile(conn net.Conn, sharedSecret *[32]byte) error {
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

	file, err := os.Create(meta.Name)
	if err != nil {
		return fmt.Errorf("could not create file: %w", err)
	}
	defer file.Close()

	bar := util.NewProgressBar(meta.Size, fmt.Sprintf("Receiving %s", meta.Name))
	defer bar.Finish()

	aead, err := crypto.NewAESGCM(sharedSecret)
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
			return fmt.Errorf("failed to decrypt chunk #%d (check passphrase): %w", chunkIndex, err)
		}

		bytesWritten, err := file.Write(decryptedChunk)
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		chunkIndex++
		bar.Add(bytesWritten)
	}
	return nil
}
