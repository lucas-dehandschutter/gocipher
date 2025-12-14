<p align="center">
  <img src="assets/logo.jpg" alt="GoCipher Logo" width="400"/>
</p>

# GoCipher

GoCipher is a secure, lightweight command-line interface (CLI) tool written in Go for encrypting and decrypting strings and files. It uses **AES-256-GCM** with **PBKDF2** key derivation to ensure your data remains safe.

## Features

*   **Strong Encryption**: Uses AES-256-GCM for authenticated encryption.
*   **Secure Key Derivation**: Derives keys from passwords using PBKDF2 with SHA-256 and a random salt.
*   **Versatile**: Supports both direct string input and file encryption/decryption.
*   **Cross-Platform**: Runs on any system where Go is supported (Windows, macOS, Linux).

## Installation

### From Source

1.  Clone the repository:
    ```bash
    git clone <repository-url>
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

Run the tool using the built binary `./gocipher` or directly with `go run main.go`.

### Flags

*   `-s, --string`: Input string to encrypt/decrypt.
*   `-f, --file`: Path to the file to encrypt/decrypt.
*   `-d, --decrypt`: Enable decryption mode (default is encryption).

### Examples

#### 1. Encrypt a String

Encrypts a text string. You will be prompted to enter a password.

```bash
./gocipher -s "Secret Message"
# Output: <hex-encoded-ciphertext>
```

#### 2. Decrypt a String

Decrypts a hex-encoded string. **Note: The `-d` flag should come before the string input or use the `-s` flag explicitly.**

```bash
./gocipher -d -s "<hex-encoded-ciphertext>"
```

#### 3. Encrypt a File

Encrypts a file (e.g., `document.txt`). The output will be saved as `document.txt.enc`.

```bash
./gocipher -f document.txt
```

#### 4. Decrypt a File

Decrypts an encrypted file (e.g., `document.txt.enc`). The output will be saved as `document.txt` (or `.dec` if the extension differs).

```bash
# Important: Place flags before the filename or use -f
./gocipher -d -f document.txt.enc
```

## Security Details

*   **Algorithm**: AES-256-GCM (Galois/Counter Mode).
*   **Key Derivation**: PBKDF2 (Password-Based Key Derivation Function 2).
    *   Hash: SHA-256
    *   Iterations: 100,000
    *   Salt: 16 bytes (randomly generated per encryption)
*   **Nonce**: 12 bytes (randomly generated per encryption)

## License

[Apache 2.0 License](LICENSE)
