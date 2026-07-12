package cmd

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/lucas-dehandschutter/gocipher/pkg/crypto"

	"golang.org/x/term"
)

// resolveInput returns the reader for a command's input: the file named by
// args[0] if one was given, or stdin otherwise (standard Unix pipe
// convention - no more separate "string mode"). filePath is "" when
// reading from stdin, which callers use to know stdin is claimed as the
// data source (and so unavailable for password entry - see readPassword).
func resolveInput(args []string) (r io.Reader, cleanup func(), filePath string, err error) {
	if len(args) > 0 {
		f, err := os.Open(args[0])
		if err != nil {
			return nil, nil, "", fmt.Errorf("error opening file: %w", err)
		}
		return f, func() { f.Close() }, args[0], nil
	}
	return os.Stdin, func() {}, "", nil
}

// prepareDecryptInput adapts the resolved input reader for decrypt: file
// input and piped stdin are always the raw encrypted stream, but stdin
// read from an interactive terminal (a human pasting ciphertext) is a
// single hex-encoded line instead.
func prepareDecryptInput(r io.Reader, fromFile bool) (io.Reader, error) {
	if fromFile || !term.IsTerminal(int(syscall.Stdin)) {
		return r, nil
	}

	fmt.Print("Enter hex-encoded ciphertext: ")
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("error reading ciphertext: %w", err)
	}
	return hex.NewDecoder(strings.NewReader(strings.TrimSpace(line))), nil
}

// resolveOutput returns the writer for a command's output: outputPath if
// given, a default "<file>.enc"/".dec" derived from inputFilePath when the
// input came from a file, or stdout otherwise.
func resolveOutput(outputPath, inputFilePath string, decrypt bool) (w io.Writer, cleanup func(), toStdout bool, err error) {
	path := outputPath
	if path == "" && inputFilePath != "" {
		if decrypt {
			if strings.HasSuffix(inputFilePath, ".enc") {
				path = strings.TrimSuffix(inputFilePath, ".enc")
			} else {
				path = inputFilePath + ".dec"
			}
		} else {
			path = inputFilePath + ".enc"
		}
	}

	if path == "" {
		return os.Stdout, func() {}, true, nil
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, nil, false, fmt.Errorf("error creating output file: %w", err)
	}
	return f, func() {
		f.Close()
		fmt.Printf("File saved to %s\n", path)
	}, false, nil
}

// readPassword reads the password used to derive the encryption key. When
// stdinIsData is true, stdin is already claimed as the input data stream
// (no file argument was given), so the password is prompted for via the
// controlling terminal (/dev/tty) instead - stdin cannot serve double duty
// as both the data pipe and the password source. Otherwise, behavior
// matches a plain interactive CLI: a masked prompt (with optional
// confirmation + entropy check) when stdin itself is a terminal, or a raw
// line read from stdin when piped (e.g. `echo "$PASS" | gocipher decrypt
// file.enc`).
func readPassword(confirm bool, stdinIsData bool) ([]byte, func(), error) {
	if stdinIsData {
		tty, err := openTTY()
		if err != nil {
			return nil, func() {}, fmt.Errorf("no controlling terminal available to prompt for a password (input is already being read from stdin): %w", err)
		}
		defer tty.Close()
		return promptPassword(int(tty.Fd()), confirm)
	}

	if term.IsTerminal(int(syscall.Stdin)) {
		return promptPassword(int(syscall.Stdin), confirm)
	}

	reader := bufio.NewReader(os.Stdin)
	pass, err := reader.ReadBytes('\n')
	if err != nil && err.Error() != "EOF" {
		return nil, func() {}, fmt.Errorf("error reading password from stdin: %w", err)
	}
	password := bytes.TrimSpace(pass)
	return password, func() { crypto.ZeroMemory(pass) }, nil
}

// promptPassword does the actual masked read (+ optional confirmation) on
// the given file descriptor.
func promptPassword(fd int, confirm bool) ([]byte, func(), error) {
	fmt.Print("Enter Password: ")
	password, err := term.ReadPassword(fd)
	fmt.Println() // Newline after password input
	if err != nil {
		return nil, func() {}, fmt.Errorf("error reading password: %w", err)
	}
	cleanup := func() { crypto.ZeroMemory(password) }

	if confirm {
		entropy, strength := crypto.EstimatePasswordStrength(password)
		fmt.Printf("Password Strength: %s (estimated entropy: %.1f bits - no dictionary check)\n", strength, entropy)

		fmt.Print("Confirm Password: ")
		byteConfirm, err := term.ReadPassword(fd)
		fmt.Println() // Newline after confirmation input
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("error reading password confirmation: %w", err)
		}
		defer crypto.ZeroMemory(byteConfirm)
		if !bytes.Equal(password, byteConfirm) {
			cleanup()
			return nil, func() {}, errors.New("passwords do not match")
		}
	}
	return password, cleanup, nil
}

// openTTY opens the process's controlling terminal directly, independent
// of stdin/stdout redirection.
func openTTY() (*os.File, error) {
	path := "/dev/tty"
	if runtime.GOOS == "windows" {
		path = "CONIN$"
	}
	return os.OpenFile(path, os.O_RDWR, 0)
}
