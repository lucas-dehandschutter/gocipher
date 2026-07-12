package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize      = 16
	nonceSize     = 12
	keySize       = 32
	chunkSize     = 64 * 1024 // 64KB
	headerSize    = 32
	headerMagic   = "GOC"
	headerVersion = 3 // Version 3 authenticates the header and a per-chunk counter in the AAD

	// AAD layout: each chunk's GCM tag authenticates the full header, the
	// chunk's flag+length, and a monotonic chunk counter. Binding the header
	// prevents tampering with the version/params/salt; binding the counter
	// makes chunk reordering and deletion detectable. Only flag+length are
	// written to the stream - the header is already written once up front, and
	// the counter is recomputed by the decryptor rather than trusted from disk.
	aadHeaderOff  = 0
	aadFlagOff    = headerSize        // 32
	aadLenOff     = aadFlagOff + 1    // 33
	aadCounterOff = aadLenOff + 4     // 37
	aadSize       = aadCounterOff + 8 // 45

	// Upper bounds on Argon2id parameters. These apply to both encryption
	// (sanity-checking user-supplied flags) and decryption (rejecting
	// oversized parameters read from an untrusted file header before
	// they're handed to argon2.IDKey, which would otherwise let a crafted
	// file force an unbounded memory/CPU allocation - a DoS vector, since
	// this happens before the password is even checked).
	maxArgon2Time    = 100             // iterations
	maxArgon2Memory  = 2 * 1024 * 1024 // KB (2 GB)
	maxArgon2Threads = 64
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
	if p.Time > maxArgon2Time {
		return fmt.Errorf("argon2id time parameter must not exceed %d", maxArgon2Time)
	}
	if p.Memory < 8 {
		return errors.New("argon2id memory parameter must be at least 8 KB")
	}
	if p.Memory > maxArgon2Memory {
		return fmt.Errorf("argon2id memory parameter must not exceed %d KB", maxArgon2Memory)
	}
	if p.Threads == 0 {
		return errors.New("argon2id threads parameter must be greater than 0")
	}
	if p.Threads > maxArgon2Threads {
		return fmt.Errorf("argon2id threads parameter must not exceed %d", maxArgon2Threads)
	}
	return nil
}

// EncryptStream encrypts data from the input reader to the output writer.
// On-wire format: Header (32) + [Flag (1) + Length (4) + Nonce (12) + Ciphertext (Variable)]...
// where Header = Magic (3) + Version (1) + Time (4) + Memory (4) + Threads (1) + Reserved (3) + Salt (16).
// Each chunk's GCM tag authenticates AAD = Header (32) + Flag (1) + Length (4) + Counter (8);
// Counter is a per-chunk sequence number that is not stored, only recomputed on decrypt.
func EncryptStream(in io.Reader, out io.Writer, password []byte, params Argon2Params) error {
	if err := params.Validate(); err != nil {
		return err
	}

	// 1. Generate random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// 2. Build and write Header (32 bytes)
	header := make([]byte, headerSize)
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
	key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, keySize)

	// 4. Initialize AES-GCM
	block, err := aes.NewCipher(key)
	ZeroMemory(key) // Wipe key material immediately after use
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// 5. Prepare buffers. aad holds the full authenticated data; its header
	// prefix is fixed for the whole stream, while flag/length/counter are set
	// per chunk. Only aad[aadFlagOff:aadCounterOff] (flag+length) is written to
	// the stream - the rest of the AAD is reconstructed on decrypt.
	nonce := make([]byte, nonceSize)
	ciphertextBuf := make([]byte, 0, chunkSize+gcm.Overhead())
	aad := make([]byte, aadSize)
	copy(aad[aadHeaderOff:], header)

	var counter uint64
	writeChunk := func(flag byte, data []byte) error {
		aad[aadFlagOff] = flag
		binary.BigEndian.PutUint32(aad[aadLenOff:], uint32(len(data)))
		binary.BigEndian.PutUint64(aad[aadCounterOff:], counter)

		// Write the on-wire chunk header (flag+length only).
		if _, err := out.Write(aad[aadFlagOff:aadCounterOff]); err != nil {
			return err
		}
		// Generate and write a fresh nonce.
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		if _, err := out.Write(nonce); err != nil {
			return err
		}
		// Encrypt, authenticating the full AAD (header + flag + length + counter).
		ciphertext := gcm.Seal(ciphertextBuf[:0], nonce, data, aad)
		if _, err := out.Write(ciphertext); err != nil {
			return err
		}
		counter++
		return nil
	}

	// 6. Processing loop
	buf := make([]byte, chunkSize)
	for {
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}

		// n=0 means the input ended exactly on a chunk boundary; fall through
		// to write the empty terminal chunk below.
		if n == 0 {
			break
		}

		// Marked Terminal Chunk: a chunk shorter than chunkSize is the last one
		// (Flag 1); a full chunk is a data chunk (Flag 0) and more follow.
		if n < chunkSize {
			return writeChunk(1, buf[:n])
		}
		if err := writeChunk(0, buf[:n]); err != nil {
			return err
		}
	}

	// 7. Edge case: input length is an exact multiple of chunkSize. The loop
	// exited on n=0 after a Flag-0 chunk, so append an empty terminal chunk to
	// signal end of stream.
	return writeChunk(1, nil)
}

// DecryptStream decrypts data from the input reader to the output writer.
func DecryptStream(in io.Reader, out io.Writer, password []byte) error {
	// 1. Read Header (32 bytes)
	header := make([]byte, headerSize)
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

	// These parameters come from the (untrusted) input file, so they must be
	// bounds-checked before being used to derive a key - otherwise a crafted
	// file could force an unbounded Argon2id memory/CPU allocation.
	headerParams := Argon2Params{Time: timeParam, Memory: memoryParam, Threads: threadsParam}
	if err := headerParams.Validate(); err != nil {
		return fmt.Errorf("invalid argon2id parameters in file header: %w", err)
	}

	// 2. Derive key using Argon2id with parameters from the header
	key := argon2.IDKey(password, salt, timeParam, memoryParam, threadsParam, keySize)

	// 3. Initialize AES-GCM
	block, err := aes.NewCipher(key)
	ZeroMemory(key) // Wipe key material immediately after use
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, nonceSize)

	// Reconstruct the AAD locally: the header we just read (fixed prefix) plus
	// each chunk's flag+length and its expected counter. The counter is never
	// read from the stream - the decryptor counts chunks itself, so a reordered
	// or deleted chunk produces a counter mismatch and fails authentication.
	aad := make([]byte, aadSize)
	copy(aad[aadHeaderOff:], header)

	var counter uint64
	for {
		// Read the on-wire chunk header (flag+length) directly into the AAD.
		if _, err := io.ReadFull(in, aad[aadFlagOff:aadCounterOff]); err != nil {
			if err == io.EOF {
				return errors.New("unexpected EOF (missing terminal chunk)")
			}
			return err
		}

		flag := aad[aadFlagOff]
		dataLen := int(binary.BigEndian.Uint32(aad[aadLenOff:]))

		// A legitimate chunk never exceeds chunkSize. Reject oversized lengths
		// before allocating, so a crafted header can't force a huge allocation
		// (the int conversion can also wrap negative on 32-bit platforms).
		if dataLen < 0 || dataLen > chunkSize {
			return errors.New("invalid chunk length")
		}

		// Bind the expected counter for this chunk's position.
		binary.BigEndian.PutUint64(aad[aadCounterOff:], counter)

		// Read Nonce
		if _, err := io.ReadFull(in, nonce); err != nil {
			return err
		}

		// Read Ciphertext
		ciphertext := make([]byte, dataLen+gcm.Overhead())
		if _, err := io.ReadFull(in, ciphertext); err != nil {
			return err
		}

		// Decrypt, authenticating the full AAD (header + flag + length + counter).
		plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return err
		}

		// Write plaintext
		if _, err := out.Write(plaintext); err != nil {
			return err
		}

		counter++

		// If Flag is 1, end of stream is reached.
		if flag == 1 {
			return nil
		}
	}
}

// Encrypt is a helper to encrypt a byte slice using the stream format.
func Encrypt(data []byte, password []byte, params Argon2Params) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(EncryptStream(&byteReader{data: data}, pw, password, params))
	}()
	return io.ReadAll(pr)
}

// Decrypt is a helper to decrypt a byte slice using the stream format.
func Decrypt(data []byte, password []byte) ([]byte, error) {
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
