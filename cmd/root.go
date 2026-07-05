package cmd

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/lucas-dehandschutter/gocipher/pkg/crypto"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	decryptMode   bool
	filePath      string
	inputString   string
	argon2Time    uint32
	argon2Memory  uint32
	argon2Threads uint8
)

var rootCmd = &cobra.Command{
	Use:   "GoCipher [string to encrypt]",
	Short: "GoCipher is a CLI tool for encryption and decryption",
	Long:  `GoCipher uses AES-256-GCM with PBKDF2 key derivation to securely encrypt and decrypt strings and files.`,
	Run: func(cmd *cobra.Command, args []string) {
		var inReader io.Reader
		var outWriter io.Writer
		var err error

		// 1. Setup Input Reader
		if filePath != "" {
			f, err := os.Open(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			inReader = f
		} else {
			var inputData string
			if inputString != "" {
				inputData = inputString
			} else if len(args) > 0 {
				inputData = strings.Join(args, " ")
			} else {
				cmd.Help()
				os.Exit(0)
			}

			// If decrypting a string, it's expected to be hex-encoded
			if decryptMode {
				// Remove newlines/spaces just in case
				inputData = strings.TrimSpace(inputData)
				inReader = hex.NewDecoder(strings.NewReader(inputData))
			} else {
				inReader = strings.NewReader(inputData)
			}
		}

		// 2. Setup Password
		var password string
		if term.IsTerminal(int(syscall.Stdin)) {
			fmt.Print("Enter Password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println() // Newline after password input
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
				os.Exit(1)
			}
			password = string(bytePassword)
		} else {
			reader := bufio.NewReader(os.Stdin)
			pass, err := reader.ReadString('\n')
			if err != nil && err.Error() != "EOF" {
				fmt.Fprintf(os.Stderr, "Error reading password from stdin: %v\n", err)
				os.Exit(1)
			}
			password = strings.TrimSpace(pass)
		}

		// 3. Setup Output Writer
		if filePath != "" {
			var outPath string
			if decryptMode {
				if strings.HasSuffix(filePath, ".enc") {
					outPath = strings.TrimSuffix(filePath, ".enc")
				} else {
					outPath = filePath + ".dec"
				}
			} else {
				outPath = filePath + ".enc"
			}

			f, err := os.Create(outPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			outWriter = f
			defer fmt.Printf("File saved to %s\n", outPath)
		} else {
			// If encrypting to stdout (string mode), use hex encoding
			if !decryptMode {
				outWriter = hex.NewEncoder(os.Stdout)
				// Add a newline at the end for terminal niceness
				defer fmt.Println()
			} else {
				outWriter = os.Stdout
			}
		}

		// 4. Perform Operation
		if decryptMode {
			err = crypto.DecryptStream(inReader, outWriter, password)
		} else {
			params := crypto.Argon2Params{
				Time:    argon2Time,
				Memory:  argon2Memory,
				Threads: argon2Threads,
			}
			err = crypto.EncryptStream(inReader, outWriter, password, params)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Operation failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&decryptMode, "decrypt", "d", false, "Decrypt mode")
	rootCmd.Flags().StringVarP(&filePath, "file", "f", "", "File to encrypt/decrypt")
	rootCmd.Flags().StringVarP(&inputString, "string", "s", "", "String to encrypt")

	// Argon2id parameter flags (only applicable during encryption)
	rootCmd.Flags().Uint32VarP(&argon2Time, "time", "t", crypto.DefaultArgon2Params.Time, "Argon2id time parameter (iterations)")
	rootCmd.Flags().Uint32VarP(&argon2Memory, "memory", "m", crypto.DefaultArgon2Params.Memory, "Argon2id memory parameter in KB (e.g. 65536 for 64MB)")
	rootCmd.Flags().Uint8VarP(&argon2Threads, "threads", "p", crypto.DefaultArgon2Params.Threads, "Argon2id threads parameter (parallelism)")
}
