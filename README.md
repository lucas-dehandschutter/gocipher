<p align="center">
  <img src="assets/logo.jpg" alt="GoCipher Logo" width="400"/>
</p>

# GoCipher

[![build](https://github.com/lucas-dehandschutter/gocipher/actions/workflows/ci.yml/badge.svg)](https://github.com/lucas-dehandschutter/gocipher/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/lucas-dehandschutter/gocipher)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/lucas-dehandschutter/gocipher)](https://github.com/lucas-dehandschutter/gocipher/releases/latest)

GoCipher is a secure, lightweight command-line interface (CLI) tool written in Go for encrypting and decrypting strings and files. It uses **AES-256-GCM** with **Argon2id** key derivation to ensure your data remains safe.

## Features

*   **Strong Encryption**: Uses AES-256-GCM for authenticated encryption.
*   **Secure Key Derivation**: Derives keys from passwords using Argon2id (resists GPU/ASIC brute-force attacks).
*   **Chunked Streaming**: Encrypts and decrypts files in 64KB blocks, protected with AAD (Associated Data) to prevent truncation or data manipulation.
*   **Versatile**: Supports both direct string input and file encryption/decryption.
*   **Cross-Platform**: Runs on any system where Go is supported (Windows, macOS, Linux).

## Installation

### Via Go Install (Recommended)

```bash
go install github.com/lucas-dehandschutter/gocipher@latest
```

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/lucas-dehandschutter/gocipher.git
    cd gocipher
    ```

2.  Build the binary:
    ```bash
    go build -o gocipher
    ```

3.  (Optional) Install to your `$GOPATH/bin`:
    ```bash
    go install
    ```

## Usage

Run the tool using the built binary `./gocipher` or directly with `go run main.go`. GoCipher exposes two subcommands, `encrypt` and `decrypt`, each taking an optional file argument. When no file is given, input is read from stdin.

```
gocipher encrypt [file] [flags]
gocipher decrypt [file] [flags]
```

### Flags

Common to both `encrypt` and `decrypt`:

*   `-o, --output`: Output path. Defaults to stdout when reading from stdin, or `<file>.enc`/`.dec`-derived when a file argument is given.

`encrypt` only (Argon2id parameters are stored in the ciphertext header, so `decrypt` reads them back automatically and does not accept these flags):

*   `-t, --time`: Argon2id time parameter (iterations, default: 3).
*   `-m, --memory`: Argon2id memory parameter in KB (default: 65536, which is 64MB).
*   `-p, --threads`: Argon2id threads parameter (parallelism, default: 4).

Passwords are always prompted for interactively (masked input) or read from a pipe — see below. There is no flag to pass a password directly, by design.

### Examples

#### 1. Encrypt text typed or piped in

No file argument means input comes from stdin. Type your text and press Ctrl+D, or pipe it in.

```bash
echo -n "Secret Message" | ./gocipher encrypt
# Output: <hex-encoded-ciphertext> (hex because stdout is a terminal; raw bytes if redirected/piped)
```

Since stdin is already used for the data here, you'll be prompted for the password via your terminal directly (not stdin) — this works whether you're typing interactively or piping data in.

#### 2. Decrypt text typed or piped in

Interactively, you'll be prompted to paste a hex-encoded ciphertext line; piped input is read as the raw encrypted stream instead.

```bash
./gocipher decrypt
Enter hex-encoded ciphertext: <paste it here>
```

#### 3. Encrypt a file

Encrypts a file (e.g., `document.txt`). The output will be saved as `document.txt.enc`.

```bash
./gocipher encrypt document.txt
```

#### 4. Decrypt a file

Decrypts an encrypted file (e.g., `document.txt.enc`). The output will be saved as `document.txt` (or `.dec` if the extension differs).

```bash
./gocipher decrypt document.txt.enc
```

#### 5. Choose your own output path

```bash
./gocipher encrypt document.txt -o secret.bin
echo -n "Secret Message" | ./gocipher encrypt -o secret.bin
```

## Security Details

*   **Algorithm**: AES-256-GCM (Galois/Counter Mode).
*   **Key Derivation**: Argon2id.
    *   Time (Iterations): 3
    *   Memory: 64 MB (65,536 KB)
    *   Threads (Parallelism): 4
    *   Salt: 16 bytes (randomly generated per encryption)
*   **Nonce**: 12 bytes (randomly generated per block)
*   **Header Format** (32 bytes):
    *   Magic Bytes: `GOC` (3 bytes)
    *   Format Version: `0x03` (1 byte)
    *   Argon2id Time: `uint32` (4 bytes, BigEndian)
    *   Argon2id Memory: `uint32` (4 bytes, BigEndian)
    *   Argon2id Threads: `uint8` (1 byte)
    *   Reserved: `3 bytes` (padding for alignment/future use, set to 0)
    *   Salt: `16 bytes`
*   **Streaming Format**: Chunked streaming (64KB chunks). Each chunk is `Flag (1) + Length (4) + Nonce (12) + Ciphertext`. The GCM tag of every chunk authenticates additional data comprising the **full header**, the chunk's flag and length, and a **monotonic chunk counter**. This binds the parameters to the payload and makes truncation, chunk reordering, and chunk deletion all detectable — decryption fails rather than silently returning altered data.

> **Note:** The version `0x03` format is not backward-compatible with files produced by earlier versions.

## License

[Apache 2.0 License](LICENSE)
