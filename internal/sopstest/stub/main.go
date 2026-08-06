// Command stub is a sops stand-in for the test suite.
//
// The keeper execs sops, so the tests need one on PATH.  Installing the real
// binary just to run "go test" would put the whole suite behind an apt
// dependency, so this stub does the same job through the sops libraries: same
// file format, same age key handling, same JSON output.
//
// It is built at test time into a temp directory and never shipped.  Nothing
// under cmd/ imports it, which is what keeps the sops dependency out of the
// four real binaries.
//
// Usage, matching the shipped decrypt_command:
//
//	stub --output-type json --decrypt <file>
package main

import (
	"fmt"
	"os"
	"time"

	sopsaes "github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	sopsformats "github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
)

func main() {
	var file string
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--output-type", "-c", "--config":
			i++ // consume the value
		case "--decrypt", "-d":
			// The file is the trailing positional argument.
		default:
			if os.Args[i][0] != '-' {
				file = os.Args[i]
			}
		}
	}
	if file == "" {
		fmt.Fprintln(os.Stderr, "stub: no file given")
		os.Exit(2)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub: %v\n", err)
		os.Exit(1)
	}

	stores := sopsconfig.NewStoresConfig()
	store := common.StoreForFormat(sopsformats.FormatForPathOrString(file, ""), stores)
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub: %v\n", err)
		os.Exit(1)
	}
	// Reads SOPS_AGE_KEY_FILE from the environment, exactly as real sops does.
	// That is the behaviour the keeper depends on, so the stub must not
	// short-circuit it.
	key, err := tree.Metadata.GetDataKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub: %v\n", err)
		os.Exit(1)
	}

	cipher := sopsaes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub: %v\n", err)
		os.Exit(1)
	}
	originalMac, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, key,
		tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil || originalMac != mac {
		fmt.Fprintln(os.Stderr, "stub: failed to verify data integrity")
		os.Exit(1)
	}

	out, err := common.StoreForFormat(sopsformats.Json, stores).EmitPlainFile(tree.Branches)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
