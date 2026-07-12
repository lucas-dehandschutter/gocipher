package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gocipher",
	Short: "GoCipher is a CLI tool for encryption and decryption",
	Long:  `GoCipher uses AES-256-GCM with Argon2id key derivation to securely encrypt and decrypt strings and files.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
}
