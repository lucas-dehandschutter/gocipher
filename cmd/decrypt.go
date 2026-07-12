package cmd

import (
	"fmt"
	"os"

	"github.com/lucas-dehandschutter/gocipher/pkg/crypto"

	"github.com/spf13/cobra"
)

var decryptOutputPath string

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt a file, or hex-encoded data piped/typed via stdin",
	Long: `Decrypts data previously encrypted with GoCipher, using the Argon2id
parameters stored in the ciphertext itself.

If [file] is given, its contents are decrypted. Otherwise, input is read
from stdin: an interactive terminal is prompted for a single hex-encoded
line (paste the output of "gocipher encrypt"), while piped input is read
as the raw encrypted stream.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inReader, closeInput, inputFilePath, err := resolveInput(args)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer closeInput()

		inReader, err = prepareDecryptInput(inReader, inputFilePath != "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		password, cleanupPassword, err := readPassword(false, inputFilePath == "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer cleanupPassword()

		outWriter, closeOutput, _, err := resolveOutput(decryptOutputPath, inputFilePath, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer closeOutput()

		if err := crypto.DecryptStream(inReader, outWriter, password); err != nil {
			fmt.Fprintf(os.Stderr, "Operation failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutputPath, "output", "o", "", "Output path (default: stdout, or derived from <file> when decrypting a file)")
}
