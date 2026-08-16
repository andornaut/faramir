// Command stub is a sops stand-in for the test suite, so "go test" is not behind
// an apt dependency: same file format, same age key handling, same output,
// through the sops libraries.  Built at test time and never shipped, and nothing
// under cmd/ imports it.
//
// Usage, matching the two shapes faramir invokes:
//
//	stub [--output-type json] --decrypt <file>
//	stub --encrypt --age <recipient>[,<recipient>...] <file>
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	sopsaes "github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	sopsformats "github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"

	"github.com/andornaut/faramir/internal/sopstest/sopsenc"
)

func main() {
	var (
		file       string
		outputType string
		recipients string
		encrypting bool
	)
	for i := 1; i < len(os.Args); i++ {
		switch arg := os.Args[i]; arg {
		case "--output-type":
			if i+1 < len(os.Args) {
				i++
				outputType = os.Args[i]
			}
		case "--age":
			if i+1 < len(os.Args) {
				i++
				recipients = os.Args[i]
			}
		case "-c", "--config":
			i++ // consume the value
		case "--encrypt", "-e":
			encrypting = true
		case "--decrypt", "-d":
			// The file is the trailing positional argument.
		default:
			if arg[0] != '-' {
				file = arg
			}
		}
	}
	if file == "" {
		fmt.Fprintln(os.Stderr, "stub: no file given")
		os.Exit(2)
	}

	var err error
	if encrypting {
		err = encrypt(file, recipients)
	} else {
		err = decrypt(file, outputType)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub: %v\n", err)
		os.Exit(1)
	}
}

func decrypt(file, outputType string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	stores := sopsconfig.NewStoresConfig()
	inFormat := sopsformats.FormatForPathOrString(file, "")
	tree, err := common.StoreForFormat(inFormat, stores).LoadEncryptedFile(data)
	if err != nil {
		return err
	}
	// SOPS_AGE_KEY_FILE from the environment, as real sops does, which is what
	// the keeper depends on.
	key, err := tree.Metadata.GetDataKey()
	if err != nil {
		return err
	}

	cipher := sopsaes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return err
	}
	originalMac, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, key,
		tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil || originalMac != mac {
		return errors.New("failed to verify data integrity")
	}

	// Without --output-type the plaintext keeps the file's own format, which is
	// what `faramir edit` edits.  The keeper asks for json.
	outFormat := inFormat
	if outputType != "" {
		outFormat = sopsformats.FormatFromString(outputType)
	}
	out, err := common.StoreForFormat(outFormat, stores).EmitPlainFile(tree.Branches)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

func encrypt(file, recipients string) error {
	if recipients == "" {
		return errors.New("--encrypt needs --age")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	format := sopsformats.FormatForPathOrString(file, "")
	branches, err := common.StoreForFormat(format, sopsconfig.NewStoresConfig()).LoadPlainFile(data)
	if err != nil {
		return err
	}
	out, err := sopsenc.Encrypt(format, strings.Split(recipients, ","), branches)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}
