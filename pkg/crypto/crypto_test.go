package crypto

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncryptDecryptStream(t *testing.T) {
	password := "securepassword"
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
	password := "helperpassword"
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

	password := "largefilepassword"

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
	password := "correct"
	wrongPassword := "wrong"
	plaintext := "Secret"

	encrypted, _ := Encrypt([]byte(plaintext), password, DefaultArgon2Params)

	// Decrypt with wrong password should fail (GCM authentication failure or invalid keyset representation)
	_, err := Decrypt(encrypted, wrongPassword)
	if err == nil {
		t.Error("Decryption with wrong password should fail")
	}
}

func TestDecryptCorruptData(t *testing.T) {
	password := "password"
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
	password := "password"
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
	password := "password"
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
	password := "custompassword"
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
}
