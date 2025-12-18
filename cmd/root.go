package cmd

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/lucas-dehandschutter/gocipher/pkg/crypto"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	decryptMode bool
	filePath    string
	inputString string
)

var rootCmd = &cobra.Command{
	Use:   "GoCipher [string to encrypt]",
	Short: "GoCipher is a CLI tool for encryption and decryption",
	Long:  `GoCipher uses AES-256-GCM with PBKDF2 key derivation to securely encrypt and decrypt strings and files.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Determine input
		var data []byte
		var err error
		var isFile bool

		if filePath != "" {
			isFile = true
			data, err = os.ReadFile(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				os.Exit(1)
			}
		} else if inputString != "" {
			data = []byte(inputString)
		} else if len(args) > 0 {
			data = []byte(strings.Join(args, " "))
		} else {
			cmd.Help()
			os.Exit(0)
		}

		// If decrypting a string (not file), decode hex
		if decryptMode && !isFile {
			decoded, err := hex.DecodeString(string(data))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding hex string: %v\n", err)
				os.Exit(1)
			}
			data = decoded
		}

		// Prompt for password
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
			// Read from stdin (pipe)
			reader := bufio.NewReader(os.Stdin)
			pass, err := reader.ReadString('\n')
			if err != nil && err.Error() != "EOF" {
				fmt.Fprintf(os.Stderr, "Error reading password from stdin: %v\n", err)
				os.Exit(1)
			}
			password = strings.TrimSpace(pass)
		}

		// Perform operation
		var result []byte
		if decryptMode {
			result, err = crypto.Decrypt(data, password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
				os.Exit(1)
			}
		} else {
			result, err = crypto.Encrypt(data, password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
				os.Exit(1)
			}
		}

		// Handle output
		if isFile {
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

			err = os.WriteFile(outPath, result, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("File saved to %s\n", outPath)
		} else {
			if decryptMode {
				fmt.Println(string(result))
			} else {
				fmt.Printf("%x\n", result)
			}
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
}
