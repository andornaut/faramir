// Package vault is the managed secret store: the sops-encrypted files under the
// config directory, and the operations that create, edit and re-seal one.
//
// It execs sops rather than linking it, which is what keeps every cloud KMS SDK
// out of the shipped binary, and it never decrypts to a path an agent could
// read: an edit goes to a private temp directory that is removed on a signal as
// well as on a return.
//
// Three rules the callers rest on:
//
//   - A file is written back only if it has not changed since it was read.
//     Two editors on one file would otherwise leave one of them silently gone.
//   - The creation rule has to cover the file before it is sealed, and must not
//     be split across a bare `age:` beside key groups. A rule that covers
//     nothing seals to nobody, and looks exactly like one that covers
//     everything.
//   - The keeper stays a reader. A re-seal that dropped it would leave a store
//     the broker can no longer open, and nothing else would have said so.
//
// It prints nothing and exits nothing: the commands in cmd/faramir report what
// it returns.
package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// sopsBinary is resolved through PATH. A variable so a test can point it
// elsewhere.
var sopsBinary = "sops"

// Edit decrypts, edits and re-encrypts one file in place, and reports
// whether the plaintext changed. Two sops runs rather than its own `sops FILE`
// mode, which picks the editor out of the environment.
func Edit(keyPath, rulePath, editorPath, target string) (bool, error) {
	// A tmpfs, so the plaintext never reaches a disk, and 0700 from MkdirTemp
	// keeps every other uid out while the editor has it open.
	dir, err := os.MkdirTemp("/dev/shm", "faramir-edit-")
	if err != nil {
		return false, fmt.Errorf("temporary directory: %w", err)
	}
	// Registered first so it runs last: defers unwind LIFO, and uninstalling the
	// handler before the directory is gone leaves a window where a signal kills
	// this process with the decrypted store still in place.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name: .sops.yaml creation rules select by path_regex, and
	// anything else would match no rule and encrypt to no recipient.
	plain := filepath.Join(dir, filepath.Base(target))

	// The recipients the file already had, named explicitly: an edit preserves
	// who could read the file, and applying a changed .sops.yaml is what `faramir
	// recipient reseal` is for. Read before the editor runs, or a file whose
	// metadata this cannot parse would be reported after the operator's edit had
	// already been made and discarded.
	recipients, err := sopsrule.SealedTo(target)
	if err != nil {
		return false, err
	}

	// Asked here for the same reason: sops refuses a file no creation rule covers
	// at the encrypt, which is after the editor has run and would cost the
	// operator everything they typed.
	if err := ruleMustCover(rulePath, target, recipients); err != nil {
		return false, err
	}

	// The ciphertext as it stands now, compared again before the write. Two edits
	// of one file each decrypt their own copy, and whichever encrypts last would
	// otherwise replace the other's work with a copy that never had it, both
	// having reported the file written.
	before, err := digestOf(target)
	if err != nil {
		return false, err
	}

	decrypted, err := runSops(keyPath, rulePath, "--decrypt", target)
	if err != nil {
		return false, fmt.Errorf("decrypt %s: %w", target, err)
	}
	if err := os.WriteFile(plain, decrypted, 0o600); err != nil {
		return false, err
	}

	cmd := exec.CommandContext(context.Background(), editorPath, plain)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Fixed: the editor runs as root, and the operator can set every variable one
	// reads for configuration.
	cmd.Env = []string{envPATH,
		"TERM=" + os.Getenv("TERM"), envLANG, "HOME=" + dir}
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("editor: %w", err)
	}

	edited, err := os.ReadFile(plain)
	if err != nil {
		return false, err
	}
	if string(edited) == string(decrypted) {
		return false, nil
	}

	reencrypted, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		// Said plainly: the plaintext goes with the tmpfs directory, and keeping it
		// would leave a decrypted store on the machine after a failed command.
		return false, fmt.Errorf("encrypt: %w. The edit was not saved, and the "+
			"decrypted copy was removed. Make it again once this is fixed", err)
	}
	if err := unchangedSince(target, before); err != nil {
		return false, err
	}
	return true, WriteBack(target, reencrypted)
}

// digestOf is the file's contents hashed, which is what says whether it is the
// one this started from.
func digestOf(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return sum[:], nil
}

// unchangedSince refuses a write onto a file something else has written since
// this read it. The edit is lost either way; what this decides is whose.
func unchangedSince(path string, before []byte) error {
	now, err := digestOf(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(now, before) {
		return fmt.Errorf("%s changed while this was working on it, so nothing was "+
			"written. Another `faramir vault edit`, `reader` or `reseal`, or a "+
			"direct write to the file, changed it first. Run this again", path)
	}
	return nil
}

// WriteBack replaces the managed file without changing who owns it, written
// beside the target and renamed so a partial failure leaves no truncated store.
//
// Both halves are made durable before this returns, this being the one
// operation that overwrites the only copy of the secrets on the host: the
// contents are flushed before the rename, or a crash leaves the new name
// pointing at a file whose data never landed, and the directory after it, or
// the rename itself is what is missing.
//
// The mode before the owner: the temporary file is created 0600 and root's, so
// widening it while it is still root:root gives nothing away.
func WriteBack(target string, data []byte) error {
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
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
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	if err := chownLike(tmp.Name(), info); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return err
	}
	// Reported and not returned: by here the replacement is the file, and what
	// failed is the promise that it survives a power loss. An error would tell
	// the operator their edit did not take, and would have `reseal` count the file
	// among those still sealed to the recipients they had.
	if err := hostfs.SyncDir(filepath.Dir(target)); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s was replaced, but %s could not be "+
			"flushed (%v), so the change may not survive a power loss until "+
			"something else syncs that filesystem\n",
			target, filepath.Dir(target), err)
	}
	return nil
}

// runSops execs sops with the key as a path (SOPS_AGE_KEY_FILE), as the keeper
// supplies it, so it is absent from any environment block in /proc. A fixed
// environment, sops reading several variables that name a key or key source.
//
// --config names the creation rules, which keeps them this host's own. Left to
// search, sops walks up from the process's working directory, which is often an
// enrolled tree the coding agent writes, and a .sops.yaml found there governs
// the encryption: `unencrypted_regex` and `unencrypted_suffix` make sops write
// the values they name in cleartext. Recipients are safe either way, the --age
// on the command line winning over a rule.
//
// The flag rather than the SOPS_CONFIG variable: a sops old enough not to know
// the variable ignores it and searches anyway, where an argument it does not
// understand is an error.
func runSops(keyPath, rulePath string, args ...string) ([]byte, error) {
	argv := append([]string{"--config", sopsConfigPath(rulePath)}, args...)
	cmd := exec.CommandContext(context.Background(), sopsBinary, argv...)
	cmd.Env = append(config.SopsEnv(), "SOPS_AGE_KEY_FILE="+keyPath)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// sealTo encrypts the plaintext copy of target and returns the ciphertext.
//
// --filename-override, because sops matches a creation rule's path_regex
// against the file it is handed, taken relative to the rule file, and what it
// is handed here is the copy in the tmpfs: a rule naming where the secrets live
// would match nothing. With the override the rule sees `secrets/<name>`, as it
// does under ordinary use.
//
// The recipients are named here rather than taken from the rule, which is what
// makes an edit preserve who could already read the file.
func sealTo(keyPath, rulePath, target string, recipients []string, plain string) ([]byte, error) {
	return runSops(keyPath, rulePath, "--encrypt",
		"--age", strings.Join(recipients, ","),
		"--filename-override", target, plain)
}

// chownLike gives the replacement the original's owner and group, so an edit
// does not hand the secrets directory back to root.
func chownLike(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner of the file being replaced")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}

// removeOnSignal removes dir when a terminating signal arrives, and returns the
// function that uninstalls the handler. A deferred cleanup does not run when
// the process does not return, and what is left behind is the whole decrypted
// store, on a tmpfs that keeps it until the machine reboots.
//
// SIGHUP is the one that happens: closing the terminal while the editor is
// open. The signal is re-raised with its default disposition afterwards, so
// the caller still sees a process killed by a signal.
func removeOnSignal(dir string) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		received, ok := <-signals
		if !ok { // uninstalled: the caller returned normally and its defer cleans up
			return
		}
		_ = os.RemoveAll(dir)
		signal.Stop(signals)
		if sig, ok := received.(syscall.Signal); ok {
			signal.Reset(sig)
			_ = syscall.Kill(os.Getpid(), sig)
		}
	}()
	return func() {
		// Stop before close, so nothing can be sent to a closed channel.
		signal.Stop(signals)
		close(signals)
	}
}
