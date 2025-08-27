# LanCrypt

[![Go Report Card](https://goreportcard.com/badge/github.com/sumanthd032/lancrypt)](https://goreportcard.com/report/github.com/sumanthd032/lancrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/sumanthd032/lancrypt)](https://github.com/sumanthd032/lancrypt/releases)

**LanCrypt** is a command-line tool for zero-knowledge, peer-to-peer, LAN-only secure file sharing.  
It enables ephemeral, end-to-end encrypted file transfers directly over a local network—without internet access, cloud servers, or persistent storage.

---

## Overview

Most file-sharing platforms (Google Drive, Dropbox, WeTransfer) rely on cloud servers, meaning your files are uploaded to third-party infrastructure where privacy is not guaranteed.  
LanCrypt solves this by creating a **direct, one-time-use connection** between devices on the same local network.

This makes it ideal for securely sending sensitive files to a colleague in the same office or a friend on the same Wi-Fi network, with the assurance that no one else can intercept or retain the data.

---

## Features

- **End-to-End Encryption**  
  X25519 for key exchange and AES-256-GCM for authenticated encryption. Files remain confidential and tamper-proof.

- **Automatic Peer Discovery**  
  mDNS (Bonjour/Zeroconf) eliminates the need to manually type IP addresses.

- **Man-in-the-Middle Protection**  
  A user-verified Short Authentication String (SAS) ensures authenticity of peers.

- **Optional Passphrase**  
  Add an extra layer of protection with a shared password, derived into the encryption key using HKDF.

- **Ephemeral & In-Memory**  
  Files are streamed directly between devices. Session keys are erased after transfer.

- **Cross-Platform**  
  Single, dependency-free binaries available for Windows, macOS, and Linux.

---

## Installation

### From GitHub Releases (Recommended)

1. Go to the [Latest Release](https://github.com/yourusername/lancrypt/releases).
2. Download the archive for your OS and architecture (e.g., `lancrypt_1.0.0_windows_amd64.zip`).
3. Extract the archive. You will have a single executable (`lancrypt` or `lancrypt.exe`).
4. Move the binary into your system's PATH.

**macOS & Linux**
```bash
sudo mv ./lancrypt /usr/local/bin/lancrypt
sudo chmod +x /usr/local/bin/lancrypt
```

**Windows**  
Move `lancrypt.exe` to a folder included in your Path environment variable (e.g., `C:\Windows\System32`).

---

## Usage

LanCrypt works with two commands: **send** and **recv**.

### 1. Sending a File
```bash
lancrypt send my_document.pdf
```

- Generates a unique transfer code (e.g., `apple-moon-robot`).
- Waits for the receiver to connect.

**Output:**
```
Sender is ready.
Your transfer code is: apple-moon-robot
On the other device, run: lancrypt recv --code apple-moon-robot
```

---

### 2. Receiving a File
```bash
lancrypt recv --code apple-moon-robot
```

- Automatically locates the sender on the network.
- Prompts for SAS verification.

---

### 3. Verifying the Connection
Both devices will display the same **Short Authentication String (SAS)**:

```
Please verify the following authentication string with the other user:

    dog-kite-vest

Do these match? (y/n):
```

If the strings match, confirm with the other person, type `y`, and the transfer begins.

---

### 4. Using a Passphrase (Optional)
```bash
# Sender
lancrypt send my_secret.zip --passphrase "a-very-secure-password"

# Receiver
lancrypt recv --code apple-moon-robot --passphrase "a-very-secure-password"
```

If the passphrases differ, SAS verification will fail and the transfer is aborted.

---

## Technology Stack

- **Language**: Go  
- **CLI Framework**: [Cobra](https://github.com/spf13/cobra)  
- **Cryptography**:  
  - `golang.org/x/crypto/curve25519` for ECDH key exchange  
  - `crypto/aes` and `crypto/cipher` for AES-256-GCM encryption  
  - `golang.org/x/crypto/hkdf` for passphrase-based key derivation  
- **Networking & Discovery**:  
  - `net` package for TCP sockets  
  - [`grandcat/zeroconf`](https://github.com/grandcat/zeroconf) for mDNS  
- **UI**: [`schollz/progressbar`](https://github.com/schollz/progressbar) for progress visualization  

---

## License

This project is licensed under the [MIT License](LICENSE).