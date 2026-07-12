package crypto

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncryptDecryptStream(t *testing.T) {
	password := []byte("securepassword")
	plaintext := "This is a secret message that needs to be encrypted."

	// Encrypt
	input := strings.NewReader(plaintext)
	var encrypted bytes.Buffer
	if err := EncryptStream(input, &encrypted, password, DefaultArgon2Params); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	var decrypted bytes.Buffer
	if err := DecryptStream(&encrypted, &decrypted, password); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted.String() != plaintext {
		t.Errorf("Decrypted text does not match plaintext.\nGot: %s\nWant: %s", decrypted.String(), plaintext)
	}
}

func TestEncryptDecryptHelpers(t *testing.T) {
	password := []byte("helperpassword")
	plaintext := []byte("Helper test data")

	// Fast encrypt
	encrypted, err := Encrypt(plaintext, password, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Encrypt helper failed: %v", err)
	}

	// Fast decrypt
	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt helper failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Helper decrypted data mismatch")
	}
}

func TestLargeDataStream(t *testing.T) {
	// 200KB data to force multiple chunks (assuming 64KB chunk size)
	size := 200 * 1024
	data := make([]byte, size)
	for i := 0; i < size; i++ {
		data[i] = byte(i % 256)
	}

	password := []byte("largefilepassword")

	input := bytes.NewReader(data)
	var encrypted bytes.Buffer

	if err := EncryptStream(input, &encrypted, password, DefaultArgon2Params); err != nil {
		t.Fatalf("Large data encryption failed: %v", err)
	}

	var decrypted bytes.Buffer
	if err := DecryptStream(&encrypted, &decrypted, password); err != nil {
		t.Fatalf("Large data decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), data) {
		t.Error("Large data decryption mismatch")
	}
}

func TestDecryptInvalidPassword(t *testing.T) {
	password := []byte("correct")
	wrongPassword := []byte("wrong")
	plaintext := "Secret"

	encrypted, _ := Encrypt([]byte(plaintext), password, DefaultArgon2Params)

	// Decrypt with wrong password should fail (GCM authentication failure or invalid keyset representation)
	_, err := Decrypt(encrypted, wrongPassword)
	if err == nil {
		t.Error("Decryption with wrong password should fail")
	}
}

func TestDecryptCorruptData(t *testing.T) {
	password := []byte("password")
	plaintext := "Secret"

	encrypted, _ := Encrypt([]byte(plaintext), password, DefaultArgon2Params)

	// Corrupt the last byte
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := Decrypt(encrypted, password)
	if err == nil {
		t.Error("Decryption of corrupted data should fail")
	}
}

func TestDecryptInvalidHeader(t *testing.T) {
	password := []byte("password")
	plaintext := "TopSecret"

	encrypted, _ := Encrypt([]byte(plaintext), password, DefaultArgon2Params)

	// TAMPERING 1: Magic bytes
	tamperedMagic := make([]byte, len(encrypted))
	copy(tamperedMagic, encrypted)
	tamperedMagic[0] = 'X' // corrupt magic
	if _, err := Decrypt(tamperedMagic, password); err == nil || !strings.Contains(err.Error(), "magic bytes") {
		t.Errorf("Expected decryption to fail with invalid magic bytes, got error: %v", err)
	}

	// TAMPERING 2: Version
	tamperedVersion := make([]byte, len(encrypted))
	copy(tamperedVersion, encrypted)
	tamperedVersion[3] = 99 // corrupt version
	if _, err := Decrypt(tamperedVersion, password); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("Expected decryption to fail with unsupported version, got error: %v", err)
	}
}

func TestDecryptTamperedFlag(t *testing.T) {
	password := []byte("password")
	plaintext := "TopSecret"

	// Create a valid encrypted stream
	encrypted, _ := Encrypt([]byte(plaintext), password, DefaultArgon2Params)

	// New Format: Header (32) + Flag (1) + Length (4) + Nonce (12) + Ciphertext...
	// The first chunk flag is at offset 32.
	// Under Marked Terminal Chunk strategy, since len("TopSecret") < 64KB,
	// this FIRST chunk is also the LAST chunk. So Flag should be 1.

	if len(encrypted) < 49 {
		t.Fatal("Encrypted data too short")
	}

	// Verify the flag is what we expect (1 = Last)
	if encrypted[32] != 1 {
		t.Fatalf("Expected flag 1 (Last) for small payload, got %d", encrypted[32])
	}

	// Verify Length (4 bytes at offset 33:37)
	dataLen := int(binary.BigEndian.Uint32(encrypted[33:37]))
	if dataLen != len(plaintext) {
		t.Fatalf("Expected length %d, got %d", len(plaintext), dataLen)
	}

	// TAMPERING 1: Change flag from 1 to 0 (claiming it's a Data chunk, not Terminal)
	// This would trick the decryptor into waiting for more data, or simply fail auth.
	tamperedFlag := make([]byte, len(encrypted))
	copy(tamperedFlag, encrypted)
	tamperedFlag[32] = 0

	if _, err := Decrypt(tamperedFlag, password); err == nil {
		t.Error("Decryption with tampered flag should have failed (AAD check)")
	}

	// TAMPERING 2: Change Length
	tamperedLen := make([]byte, len(encrypted))
	copy(tamperedLen, encrypted)
	tamperedLen[36] = byte(dataLen + 1) // Modify last byte of length

	if _, err := Decrypt(tamperedLen, password); err == nil {
		t.Error("Decryption with tampered length should have failed (AAD check)")
	}
}

func TestEncryptDecryptCustomParams(t *testing.T) {
	password := []byte("custompassword")
	plaintext := "Testing custom parameters for Argon2id."

	params := Argon2Params{
		Time:    1,
		Memory:  16 * 1024, // 16MB
		Threads: 2,
	}

	// Encrypt
	input := strings.NewReader(plaintext)
	var encrypted bytes.Buffer
	if err := EncryptStream(input, &encrypted, password, params); err != nil {
		t.Fatalf("Encryption with custom params failed: %v", err)
	}

	// Verify header contents
	headerBytes := encrypted.Bytes()
	if len(headerBytes) < 32 {
		t.Fatalf("Encrypted stream too short, expected at least 32-byte header")
	}

	// Read and check Time, Memory, Threads from header
	timeVal := binary.BigEndian.Uint32(headerBytes[4:8])
	memVal := binary.BigEndian.Uint32(headerBytes[8:12])
	threadsVal := headerBytes[12]

	if timeVal != params.Time {
		t.Errorf("Time parameter in header mismatch: got %d, want %d", timeVal, params.Time)
	}
	if memVal != params.Memory {
		t.Errorf("Memory parameter in header mismatch: got %d, want %d", memVal, params.Memory)
	}
	if threadsVal != params.Threads {
		t.Errorf("Threads parameter in header mismatch: got %d, want %d", threadsVal, params.Threads)
	}

	// Decrypt (it should automatically read the custom params from the header)
	var decrypted bytes.Buffer
	if err := DecryptStream(&encrypted, &decrypted, password); err != nil {
		t.Fatalf("Decryption with custom params failed: %v", err)
	}

	if decrypted.String() != plaintext {
		t.Errorf("Decrypted custom text mismatch: got %s, want %s", decrypted.String(), plaintext)
	}
}

func TestArgon2ParamsValidation(t *testing.T) {
	t.Run("Time is zero", func(t *testing.T) {
		p := Argon2Params{Time: 0, Memory: 1024, Threads: 1}
		if err := p.Validate(); err == nil {
			t.Error("Expected validation error for Time = 0")
		}
	})

	t.Run("Memory is too low", func(t *testing.T) {
		p := Argon2Params{Time: 1, Memory: 4, Threads: 1}
		if err := p.Validate(); err == nil {
			t.Error("Expected validation error for Memory < 8 KB")
		}
	})

	t.Run("Threads is zero", func(t *testing.T) {
		p := Argon2Params{Time: 1, Memory: 1024, Threads: 0}
		if err := p.Validate(); err == nil {
			t.Error("Expected validation error for Threads = 0")
		}
	})

	t.Run("Valid parameters", func(t *testing.T) {
		p := Argon2Params{Time: 1, Memory: 8, Threads: 1}
		if err := p.Validate(); err != nil {
			t.Errorf("Unexpected validation error for valid parameters: %v", err)
		}
	})

	t.Run("Time is too high", func(t *testing.T) {
		p := Argon2Params{Time: maxArgon2Time + 1, Memory: 1024, Threads: 1}
		if err := p.Validate(); err == nil {
			t.Error("Expected validation error for Time above the maximum")
		}
	})

	t.Run("Memory is too high", func(t *testing.T) {
		p := Argon2Params{Time: 1, Memory: maxArgon2Memory + 1, Threads: 1}
		if err := p.Validate(); err == nil {
			t.Error("Expected validation error for Memory above the maximum")
		}
	})

	t.Run("Threads is too high", func(t *testing.T) {
		p := Argon2Params{Time: 1, Memory: 1024, Threads: maxArgon2Threads + 1}
		if err := p.Validate(); err == nil {
			t.Error("Expected validation error for Threads above the maximum")
		}
	})
}

// TestDecryptRejectsOversizedHeaderParams ensures a crafted/tampered file
// cannot force an oversized Argon2id memory allocation by smuggling huge
// parameters through the (otherwise untrusted) file header.
func TestDecryptRejectsOversizedHeaderParams(t *testing.T) {
	password := []byte("password")
	plaintext := []byte("Secret")

	encrypted, err := Encrypt(plaintext, password, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with the Memory field (header bytes 8:12) to an unreasonably
	// large value, as an attacker crafting a malicious file might.
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	binary.BigEndian.PutUint32(tampered[8:12], maxArgon2Memory+1)

	_, err = Decrypt(tampered, password)
	if err == nil {
		t.Fatal("Expected decryption to fail for oversized Memory parameter in header")
	}
	if !strings.Contains(err.Error(), "invalid argon2id parameters") {
		t.Errorf("Expected error about invalid argon2id parameters, got: %v", err)
	}
}

// splitStream parses a v3 encrypted stream into its 32-byte header and the
// raw on-wire bytes of each chunk (Flag + Length + Nonce + Ciphertext).
func splitStream(t *testing.T, stream []byte) (header []byte, chunks [][]byte) {
	t.Helper()
	if len(stream) < 32 {
		t.Fatalf("stream shorter than header: %d bytes", len(stream))
	}
	header = stream[:32]
	rest := stream[32:]
	for len(rest) > 0 {
		if len(rest) < 5+nonceSize {
			t.Fatalf("truncated chunk header")
		}
		dataLen := int(binary.BigEndian.Uint32(rest[1:5]))
		total := 5 + nonceSize + dataLen + 16 // flag+length + nonce + ciphertext+tag
		if len(rest) < total {
			t.Fatalf("truncated chunk body: need %d, have %d", total, len(rest))
		}
		chunks = append(chunks, rest[:total])
		rest = rest[total:]
	}
	return header, chunks
}

func reassemble(header []byte, chunks [][]byte) []byte {
	out := append([]byte{}, header...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// TestDecryptDetectsChunkReordering ensures that swapping two data chunks is
// caught by the per-chunk counter bound into the AAD.
func TestDecryptDetectsChunkReordering(t *testing.T) {
	password := []byte("password")
	data := make([]byte, 2*chunkSize+500) // two full data chunks + a terminal chunk
	for i := range data {
		data[i] = byte(i)
	}

	encrypted, err := Encrypt(data, password, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	header, chunks := splitStream(t, encrypted)
	if len(chunks) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(chunks))
	}

	// Swap the two full-size data chunks.
	chunks[0], chunks[1] = chunks[1], chunks[0]
	tampered := reassemble(header, chunks)

	if _, err := Decrypt(tampered, password); err == nil {
		t.Error("expected reordered chunks to fail authentication")
	}
}

// TestDecryptDetectsChunkDeletion ensures that removing an interior chunk is
// caught: all following chunks shift down, so their counters no longer match.
func TestDecryptDetectsChunkDeletion(t *testing.T) {
	password := []byte("password")
	data := make([]byte, 2*chunkSize+500)
	for i := range data {
		data[i] = byte(i)
	}

	encrypted, err := Encrypt(data, password, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	header, chunks := splitStream(t, encrypted)
	if len(chunks) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(chunks))
	}

	// Drop the first data chunk; the second now sits where the first was and
	// will be checked against the wrong counter.
	tampered := reassemble(header, chunks[1:])

	if _, err := Decrypt(tampered, password); err == nil {
		t.Error("expected a deleted chunk to fail authentication")
	}
}

// TestDecryptDetectsHeaderTampering ensures the header is now authenticated:
// flipping even a reserved byte (previously ignored) breaks decryption.
func TestDecryptDetectsHeaderTampering(t *testing.T) {
	password := []byte("password")
	encrypted, err := Encrypt([]byte("secret"), password, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[13] ^= 0xFF // reserved byte, not used by the KDF or version/magic checks

	if _, err := Decrypt(tampered, password); err == nil {
		t.Error("expected tampering with a reserved header byte to fail authentication")
	}
}

// TestDecryptRejectsOversizedChunkLength ensures a crafted chunk length can't
// force a huge allocation before authentication.
func TestDecryptRejectsOversizedChunkLength(t *testing.T) {
	password := []byte("password")
	encrypted, err := Encrypt([]byte("secret"), password, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	// Length is 4 bytes at offset 33 (after the 32-byte header + 1 flag byte).
	binary.BigEndian.PutUint32(tampered[33:37], chunkSize+1)

	_, err = Decrypt(tampered, password)
	if err == nil || !strings.Contains(err.Error(), "invalid chunk length") {
		t.Errorf("expected 'invalid chunk length' error, got: %v", err)
	}
}

func TestEstimatePasswordStrength(t *testing.T) {
	tests := []struct {
		password  []byte
		wantLabel string
	}{
		{[]byte(""), "Empty"},
		{[]byte("weak"), "Weak"},
		{[]byte("Medium123"), "Medium"},
		{[]byte("StrongPw1!"), "Strong"},
		{[]byte("ExtremelyLongAndComplexPassword123!@#$"), "Very Strong"},
	}

	for _, tt := range tests {
		_, gotLabel := EstimatePasswordStrength(tt.password)
		// Clean up ANSI color codes for assertion
		gotLabelClean := gotLabel
		gotLabelClean = strings.ReplaceAll(gotLabelClean, "\033[31m", "")
		gotLabelClean = strings.ReplaceAll(gotLabelClean, "\033[33m", "")
		gotLabelClean = strings.ReplaceAll(gotLabelClean, "\033[32m", "")
		gotLabelClean = strings.ReplaceAll(gotLabelClean, "\033[32;1m", "")
		gotLabelClean = strings.ReplaceAll(gotLabelClean, "\033[0m", "")

		if gotLabelClean != tt.wantLabel {
			t.Errorf("EstimatePasswordStrength(%q) = %q, want %q", tt.password, gotLabelClean, tt.wantLabel)
		}
	}
}

func TestZeroMemory(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroMemory(b)
	for i, val := range b {
		if val != 0 {
			t.Errorf("Expected byte at index %d to be 0, got %d", i, val)
		}
	}
}
