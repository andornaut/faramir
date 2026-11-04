package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/hostfs"
)

// Add writes the new file, with the plaintext living only in a tmpfs.
// The same shape as an edit minus the decrypt, and the recipients come from the
// rule rather than from the file, which has none yet.
func Add(keyPath, rulePath, editorPath, from, target string) error {
	name := managedStem(target)
	dir, err := os.MkdirTemp("/dev/shm", "faramir-add-")
	if err != nil {
		return fmt.Errorf("%s not saved: %w", name, err)
	}
	// Registered first so it runs last; see editManaged.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name: .sops.yaml creation rules select by path_regex, and
	// anything else would match no rule and encrypt to no recipient.
	plain := filepath.Join(dir, filepath.Base(target))

	recipients, err := ruleFor(rulePath, target)
	if err != nil {
		return err
	}

	if err := fillPlaintext(editorPath, from, dir, plain); err != nil {
		return fmt.Errorf("%s not saved: %w", name, err)
	}

	sealed, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		return fmt.Errorf("%s not saved: %w", name, err)
	}
	if err := createManaged(target, sealed); err != nil {
		return fmt.Errorf("%s not saved: %w", name, err)
	}
	return nil
}

// RuleCovers is the question Add asks of the rule before any content exists:
// that it names the recipients and has a creation rule for target. What `vault
// add --dry-run` checks, so a preview and a real run refuse the same rule.
func RuleCovers(rulePath, target string) error {
	_, err := ruleFor(rulePath, target)
	return err
}

// ruleFor is the recipients a new file at target is sealed to. Asked before the
// editor opens, as an edit asks it: sops refuses a file no creation rule covers
// at the encrypt, after everything has been typed.
func ruleFor(rulePath, target string) ([]string, error) {
	recipients, err := RuleRecipients(rulePath)
	if err != nil {
		return nil, err
	}
	if err := ruleMustCover(rulePath, target, recipients); err != nil {
		return nil, err
	}
	return recipients, nil
}

// fillPlaintext puts the content in the tmpfs, from a file or from an editor.
func fillPlaintext(editorPath, from, dir, plain string) error {
	if from != "" {
		body, err := os.ReadFile(from)
		if err != nil {
			return fserr.At(from, err)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return fmt.Errorf("%s is empty", from)
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
		return fmt.Errorf("%s: %w", editorPath, err)
	}
	body, err := os.ReadFile(plain)
	if err != nil {
		return err
	}
	// An empty file is how somebody says they changed their mind, and creating
	// one leaves a managed file naming no ref for the broker to serve.
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("the editor left it empty")
	}
	return nil
}

// createManaged writes a file that was not there before, 0640 like every other
// managed one. The group comes from the secrets directory, which is setgid to
// the keeper's, so a new file is readable by the daemon that opens it without
// this naming an account. Published with link(2), which refuses an existing
// name: another add may have created the target while this run's editor was
// open. Not renameat2(RENAME_NOREPLACE), which eCryptfs rejects with EINVAL.
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
	// 0640 rather than tighter: the keeper's group has to open it. Set the mode
	// before syncing so the contents and their final permissions are durable.
	if err := tmp.Chmod(0o640); err != nil {
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
	return withPublicationLock(func() error {
		if err := unix.Link(tmp.Name(), target); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return &existsError{target: target, err: err}
			}
			return fmt.Errorf("%s: %w", target, err)
		}
		// Before the directory sync, so the durable state is the target alone.
		if err := os.Remove(tmp.Name()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s written, but %s was not removed: %v\n", target, tmp.Name(), err)
		}
		if err := hostfs.SyncDir(filepath.Dir(target)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s written, but its directory was not synced: %v\n", target, err)
		}
		return nil
	}, target)
}

// existsError is a target another add created first. The errno stays reachable
// through Unwrap and out of the message, which says the same in words.
type existsError struct {
	target string
	err    error
}

func (e *existsError) Error() string {
	return fmt.Sprintf("%s already exists; nothing was replaced. Edit it with "+
		"`faramir vault edit %s`", e.target, managedStem(e.target))
}

func (e *existsError) Unwrap() error { return e.err }
