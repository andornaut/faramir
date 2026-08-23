// Package sopstest builds encrypted fixtures and a sops stand-in for tests.
// Imported only from _test.go files, so the sops libraries reach test binaries
// and never the shipped one: the keeper execs sops rather than linking it,
// which keeps every cloud KMS SDK out of what installs on a host. CI fails on
// a getsops hit in "go list -deps ./cmd/faramir".
package sopstest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"filippo.io/age"
	sops "github.com/getsops/sops/v3"
	sopsformats "github.com/getsops/sops/v3/cmd/sops/formats"

	"github.com/andornaut/faramir/internal/sopstest/sopsenc"
)

// NewIdentity mints an age keypair and writes the identity into dir.
func NewIdentity(t *testing.T, dir string) (keyPath, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "age.key")
	if err := os.WriteFile(keyPath, []byte(id.String()+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return keyPath, id.Recipient().String()
}

// WriteEncrypted builds a sops-encrypted YAML file addressed to recipient.
func WriteEncrypted(t *testing.T, path, recipient string, branch sops.TreeBranch) {
	t.Helper()
	out, err := sopsenc.Encrypt(sopsformats.Yaml, []string{recipient}, sops.TreeBranches{branch})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	stubOnce sync.Once
	stubPath string
	errStub  error
)

// SopsBinary returns a sops-compatible binary for the keeper to exec: the real
// one when installed, otherwise the stub, built once per run.
func SopsBinary(t *testing.T) string {
	t.Helper()
	if installed, err := exec.LookPath("sops"); err == nil {
		return installed
	}
	stubOnce.Do(func() {
		// One directory, reused by every run on this machine, rather than one per
		// test binary: the stub outlives the test that built it, so nothing here
		// can remove it, and a fresh temporary directory each time leaves a 60MB
		// binary behind on every `go test`. The user's cache rather than a name in
		// /tmp that any account could have made first.
		dir, err := stubDir()
		if err != nil {
			errStub = err
			return
		}
		out := filepath.Join(dir, "sops")
		// Built under a name of this process's own and moved into place, so two
		// `go test` runs at once do not write the same file. The rename is atomic
		// and a run already executing the old binary keeps it.
		staged := fmt.Sprintf("%s.%d", out, os.Getpid())
		cmd := exec.CommandContext(t.Context(), "go", "build", "-o", staged,
			"github.com/andornaut/faramir/internal/sopstest/stub")
		if combined, err := cmd.CombinedOutput(); err != nil {
			errStub = err
			t.Logf("building sops stub: %s", combined)
			return
		}
		if err := os.Rename(staged, out); err != nil {
			errStub = err
			_ = os.Remove(staged)
			return
		}
		stubPath = out
	})
	if errStub != nil {
		t.Skipf("no sops binary and the stub would not build: %v", errStub)
	}
	return stubPath
}

// stubDir is where the stub binary lives between runs: one directory per user,
// so a machine holds one copy however many times the suite runs. os.TempDir is
// the fallback, and only there because a cache directory is not guaranteed.
func stubDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return os.MkdirTemp("", "faramir-sops-stub-")
	}
	dir := filepath.Join(cache, "faramir", "sops-stub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// DecryptCommand is the [secret] decrypt_command for a test, pointed at
// whichever sops binary SopsBinary found or built.
func DecryptCommand(t *testing.T) []string {
	t.Helper()
	return []string{SopsBinary(t), "--output-type", "json", "--decrypt", "{file}"}
}
