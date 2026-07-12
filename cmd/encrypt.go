package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"

	"github.com/lucas-dehandschutter/gocipher/pkg/crypto"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	encryptOutputPath string
	argon2Time        uint32
	argon2Memory      uint32
	argon2Threads     uint8
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a file, or data piped/typed via stdin",
	Long: `Encrypts data using AES-256-GCM with a key derived from your password via Argon2id.

If [file] is given, its contents are encrypted and saved to <file>.enc by
default. Otherwise, input is read from stdin - pipe data in, or type it
interactively and press Ctrl+D when done.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inReader, closeInput, inputFilePath, err := resolveInput(args)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer closeInput()

		if inputFilePath == "" && term.IsTerminal(int(syscall.Stdin)) {
			fmt.Fprintln(os.Stderr, "No file given, reading from stdin (press Ctrl+D when done)...")
		}

		password, cleanupPassword, err := readPassword(true, inputFilePath == "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer cleanupPassword()

		outWriter, closeOutput, toStdout, err := resolveOutput(encryptOutputPath, inputFilePath, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer closeOutput()

		if toStdout && term.IsTerminal(int(syscall.Stdout)) {
			// Hex-encode when writing straight to an interactive terminal,
			// so the ciphertext is readable/copyable rather than raw bytes.
			outWriter = hex.NewEncoder(outWriter)
			defer fmt.Println()
		}

		params := crypto.Argon2Params{
			Time:    argon2Time,
			Memory:  argon2Memory,
			Threads: argon2Threads,
		}
		if err := crypto.EncryptStream(inReader, outWriter, password, params); err != nil {
			fmt.Fprintf(os.Stderr, "Operation failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	encryptCmd.Flags().StringVarP(&encryptOutputPath, "output", "o", "", "Output path (default: stdout, or <file>.enc when encrypting a file)")

	encryptCmd.Flags().Uint32VarP(&argon2Time, "time", "t", crypto.DefaultArgon2Params.Time, "Argon2id time parameter (iterations)")
	encryptCmd.Flags().Uint32VarP(&argon2Memory, "memory", "m", crypto.DefaultArgon2Params.Memory, "Argon2id memory parameter in KB (e.g. 65536 for 64MB)")
	encryptCmd.Flags().Uint8VarP(&argon2Threads, "threads", "p", crypto.DefaultArgon2Params.Threads, "Argon2id threads parameter (parallelism)")
}
