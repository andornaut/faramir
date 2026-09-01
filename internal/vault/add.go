package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/andornaut/faramir/internal/fserr"
)

// Add writes the new file, with the plaintext living only in a tmpfs.
// The same shape as an edit minus the decrypt, and the recipients come from the
// rule rather than from the file, which has none yet.
func Add(keyPath, rulePath, editorPath, from, target string) error {
	dir, err := os.MkdirTemp("/dev/shm", "faramir-add-")
	if err != nil {
		return fmt.Errorf("temporary directory: %w", err)
	}
	// Registered first so it runs last; see editManaged.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name: .sops.yaml creation rules select by path_regex, and
	// anything else would match no rule and encrypt to no recipient.
	plain := filepath.Join(dir, filepath.Base(target))

	recipients, err := RuleRecipients(rulePath)
	if err != nil {
		return err
	}
	// Asked before the editor opens, as an edit asks it: sops refuses a file no
	// creation rule covers at the encrypt, after everything has been typed.
	if err := ruleMustCover(rulePath, target, recipients); err != nil {
		return err
	}

	if err := fillPlaintext(editorPath, from, dir, plain); err != nil {
		return err
	}

	sealed, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		return fmt.Errorf("encrypt: %w. Nothing was written and the decrypted copy "+
			"has been removed, so make it again once this is fixed", err)
	}
	return createManaged(target, sealed)
}

// fillPlaintext puts the content in the tmpfs, from a file or from an editor.
func fillPlaintext(editorPath, from, dir, plain string) error {
	if from != "" {
		body, err := os.ReadFile(from)
		if err != nil {
			return fserr.At(from, err)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return fmt.Errorf("%s holds nothing, and an encrypted file with nothing in "+
				"it names no ref", from)
		}
		return os.WriteFile(plain, body, 0o600)
	}
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(context.Background(), editorPath, plain)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Fixed: the editor runs as root, and the operator can set every variable one
	// reads for configuration.
	cmd.Env = []string{envPATH,
		"TERM=" + os.Getenv("TERM"), envLANG, "HOME=" + dir}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}
	body, err := os.ReadFile(plain)
	if err != nil {
		return err
	}
	// An empty file is how somebody says they changed their mind, and creating
	// one leaves a managed file naming no ref for the broker to serve.
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("nothing was written, so no file was created")
	}
	return nil
}

// createManaged writes a file that was not there before, 0640 like every other
// managed one. The group comes from the secrets directory, which is setgid to
// the keeper's, so a new file is readable by the daemon that opens it without
// this naming an account. Written beside the target and renamed, and made
// durable, for the reasons writeBack does it.
func createManaged(target string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// 0640 rather than tighter: the keeper's group has to open it. The same mode
	// every other managed file carries.
	if err := os.Chmod(tmp.Name(), 0o640); err != nil { //nolint:gosec // G302: the keeper's group reads the store
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s was written, but %s could not be flushed "+
			"(%v), so it may not survive a power loss until something else syncs that "+
			"filesystem\n", target, filepath.Dir(target), err)
	}
	return nil
}
