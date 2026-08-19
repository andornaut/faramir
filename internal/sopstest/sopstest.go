// Package sopstest builds encrypted fixtures and a sops stand-in for tests.
// Imported only from _test.go files, so the sops libraries reach test binaries
// and never the shipped one: the keeper execs sops rather than linking it,
// which keeps every cloud KMS SDK out of what installs on a host. CI fails on
// a getsops hit in "go list -deps ./cmd/faramir".
package sopstest

import (
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
		// Not t.TempDir: the stub is built once and used by every test after this
		// one, and a directory removed when this test ends takes the binary with
		// it.
		dir, err := os.MkdirTemp("", "faramir-sops-stub-") //nolint:usetesting // outlives this test on purpose
		if err != nil {
			errStub = err
			return
		}
		out := filepath.Join(dir, "sops")
		cmd := exec.CommandContext(t.Context(), "go", "build", "-o", out,
			"github.com/andornaut/faramir/internal/sopstest/stub")
		if combined, err := cmd.CombinedOutput(); err != nil {
			errStub = err
			t.Logf("building sops stub: %s", combined)
			return
		}
		stubPath = out
	})
	if errStub != nil {
		t.Skipf("no sops binary and the stub would not build: %v", errStub)
	}
	return stubPath
}

// DecryptCommand is the [secret] decrypt_command for a test, pointed at
// whichever sops binary SopsBinary found or built.
func DecryptCommand(t *testing.T) []string {
	t.Helper()
	return []string{SopsBinary(t), "--output-type", "json", "--decrypt", "{file}"}
}
