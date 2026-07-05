package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize      = 16
	nonceSize     = 12
	keySize       = 32
	chunkSize     = 64 * 1024 // 64KB
	headerMagic   = "GOC"
	headerVersion = 2 // Version 2 corresponds to 0.2.0 with Argon2id
)

// Argon2Params defines the parameters used for key derivation via Argon2id.
type Argon2Params struct {
	Time    uint32 // Number of passes over the memory
	Memory  uint32 // Memory size in KB (e.g. 65536 for 64MB)
	Threads uint8  // Degree of parallelism (number of threads)
}

// DefaultArgon2Params defines the default Argon2id parameters recommended by OWASP
// for resource-constrained environments (3 iterations, 64MB memory, 4 threads).
var DefaultArgon2Params = Argon2Params{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 4,
}

// Validate checks if the Argon2id parameters are within safe and valid bounds.
func (p Argon2Params) Validate() error {
	if p.Time == 0 {
		return errors.New("argon2id time parameter must be greater than 0")
	}
	if p.Memory < 8 {
		return errors.New("argon2id memory parameter must be at least 8 KB")
	}
	if p.Threads == 0 {
		return errors.New("argon2id threads parameter must be greater than 0")
	}
	return nil
}

// EncryptStream encrypts data from the input reader to the output writer.
// Format: Magic (3) + Version (1) + Time (4) + Memory (4) + Threads (1) + Reserved (3) + Salt (16) + [Flag (1) + Length (4) + Nonce (12) + Ciphertext (Variable)]...
func EncryptStream(in io.Reader, out io.Writer, password string, params Argon2Params) error {
	if err := params.Validate(); err != nil {
		return err
	}

	// 1. Generate random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// 2. Write Header (32 bytes)
	header := make([]byte, 32)
	copy(header[0:3], headerMagic)
	header[3] = headerVersion
	binary.BigEndian.PutUint32(header[4:8], params.Time)
	binary.BigEndian.PutUint32(header[8:12], params.Memory)
	header[12] = params.Threads
	// header[13:16] are reserved (0)
	copy(header[16:32], salt)

	if _, err := out.Write(header); err != nil {
		return err
	}

	// 3. Derive key from password using Argon2id
	key := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, keySize)

	// 4. Initialize AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// 5. Prepare buffers
	buf := make([]byte, chunkSize)
	nonce := make([]byte, nonceSize)
	ciphertextBuf := make([]byte, 0, chunkSize+gcm.Overhead())

	// Buffer for Flag (1) + Length (4) = 5 bytes (AAD)
	aadBuf := make([]byte, 5)

	// 6. Processing loop
	for {
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}

		// If n=0, the file ended exactly on a block boundary.
		// We must write an empty terminal chunk.
		if n == 0 {
			break
		}

		// Marked Terminal Chunk logic:
		// - If n < 64KB: This is the last chunk (Flag 1). Write and return.
		// - If n == 64KB: This is a data chunk (Flag 0). Continue.

		flag := byte(0) // Default: Data Chunk
		isLast := false

		if n < chunkSize {
			flag = 1 // Terminal Chunk
			isLast = true
		}

		// --- Write Header ---

		// Set Flag and Length in AAD buffer
		aadBuf[0] = flag
		binary.BigEndian.PutUint32(aadBuf[1:], uint32(n))

		if _, err := out.Write(aadBuf); err != nil {
			return err
		}

		// Generate and write Nonce
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		if _, err := out.Write(nonce); err != nil {
			return err
		}

		// Encrypt (Authenticated with AAD)
		ciphertext := gcm.Seal(ciphertextBuf[:0], nonce, buf[:n], aadBuf)

		if _, err := out.Write(ciphertext); err != nil {
			return err
		}

		// If this was a partial block, stream is complete.
		if isLast {
			return nil
		}
	}

	// 7. Edge Case: File size is a multiple of 64KB
	// The loop exited because n=0. The last written chunk was Flag 0.
	// We must append an empty terminal chunk (Flag 1, Length 0) to signal end of stream.
	{
		flag := byte(1)
		aadBuf[0] = flag
		binary.BigEndian.PutUint32(aadBuf[1:], 0) // Length 0

		if _, err := out.Write(aadBuf); err != nil {
			return err
		}

		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		if _, err := out.Write(nonce); err != nil {
			return err
		}

		ciphertext := gcm.Seal(ciphertextBuf[:0], nonce, nil, aadBuf)
		if _, err := out.Write(ciphertext); err != nil {
			return err
		}
	}

	return nil
}

// DecryptStream decrypts data from the input reader to the output writer.
func DecryptStream(in io.Reader, out io.Writer, password string) error {
	// 1. Read Header (32 bytes)
	header := make([]byte, 32)
	if _, err := io.ReadFull(in, header); err != nil {
		return err
	}

	// Validate magic
	if string(header[0:3]) != headerMagic {
		return errors.New("invalid file format (missing magic bytes)")
	}

	// Validate version
	if header[3] != headerVersion {
		return errors.New("unsupported file format version")
	}

	// Extract Argon2id parameters
	timeParam := binary.BigEndian.Uint32(header[4:8])
	memoryParam := binary.BigEndian.Uint32(header[8:12])
	threadsParam := header[12]
	// header[13:16] are reserved
	salt := header[16:32]

	// 2. Derive key using Argon2id with parameters from the header
	key := argon2.IDKey([]byte(password), salt, timeParam, memoryParam, threadsParam, keySize)

	// 3. Initialize AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, nonceSize)
	aadBuf := make([]byte, 5)

	for {
		// Read Header (AAD): Flag + Length
		if _, err := io.ReadFull(in, aadBuf); err != nil {
			if err == io.EOF {
				return errors.New("unexpected EOF (missing terminal chunk)")
			}
			return err
		}

		flag := aadBuf[0]
		dataLen := int(binary.BigEndian.Uint32(aadBuf[1:]))

		// Read Nonce
		if _, err := io.ReadFull(in, nonce); err != nil {
			return err
		}

		// Read Ciphertext
		ciphertext := make([]byte, dataLen+gcm.Overhead())
		if _, err := io.ReadFull(in, ciphertext); err != nil {
			return err
		}

		// Decrypt using AAD (Flag + Length)
		plaintext, err := gcm.Open(nil, nonce, ciphertext, aadBuf)
		if err != nil {
			return err
		}

		// Write plaintext
		if _, err := out.Write(plaintext); err != nil {
			return err
		}

		// If Flag is 1, end of stream is reached.
		if flag == 1 {
			return nil
		}
	}
}

// Encrypt is a helper to encrypt a byte slice using the stream format.
func Encrypt(data []byte, password string, params Argon2Params) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(EncryptStream(&byteReader{data: data}, pw, password, params))
	}()
	return io.ReadAll(pr)
}

// Decrypt is a helper to decrypt a byte slice using the stream format.
func Decrypt(data []byte, password string) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(DecryptStream(&byteReader{data: data}, pw, password))
	}()
	return io.ReadAll(pr)
}

// byteReader helper to adapt []byte to io.Reader
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return
}
