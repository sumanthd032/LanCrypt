# LanCrypt

**Zero-knowledge, peer-to-peer, LAN-only secure file sharing.**

LanCrypt is a command-line tool that enables ephemeral, end-to-end encrypted file sharing directly over a local network. It leaves no trace, uses no cloud servers, and does not require an internet connection.

## The Problem

Most file-sharing platforms (Google Drive, Dropbox, WeTransfer) rely on cloud servers, meaning your files are uploaded to third-party storage where privacy is not guaranteed. LanCrypt solves this by creating a direct, secure, one-time-use connection between two devices on the same local network.

## Key Features

- **End-to-End Encryption:** Using `X25519` for key exchange and `AES-256-GCM` for authenticated encryption.
- **Zero Persistence:** Files are streamed from memory and are never stored on an intermediary disk or server. Sessions are destroyed immediately after a transfer.
- **Man-in-the-Middle Protection:** A Short Authentication String (SAS) allows users to verify their connection is secure.
- **Automatic Discovery:** Uses `mDNS` (Zeroconf/Bonjour) to automatically find peers on the network, no IP addresses required.
- **Passphrase Protection:** Optional passphrase can be added for an extra layer of security.

## Installation

First, ensure you have [Go](https://go.dev/doc/install) installed on your system.

Then, you can build the `lancrypt` binary from source:

```bash
# Clone the repository (or use your local directory)
# git clone [https://github.com/sumanthd032/lancrypt.git](https://github.com/sumanthd032/lancrypt.git)
cd lancrypt

# Build the binary
go build -o lancrypt ./cmd/lancrypt