// Package sopstest builds encrypted fixtures and a sops stand-in for tests.
//
// It is imported only from _test.go files.  That is deliberate and load-
// bearing: the sops libraries live here and in ./stub, so they are linked into
// test binaries and never into the shipped one.  The keeper execs sops rather
// than linking it, which is what keeps every cloud KMS SDK sops supports out of
// what installs on a host.  Run "go list -deps ./cmd/faramir | grep getsops" to
// confirm; CI fails on a hit.
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
	stubErr  error
)

// SopsBinary returns a path to a sops-compatible binary for the keeper to exec.
//
// The real binary is preferred when it is installed, so a machine that has one
// tests against it.  Otherwise the stub is built once per run.
func SopsBinary(t *testing.T) string {
	t.Helper()
	if real, err := exec.LookPath("sops"); err == nil {
		return real
	}
	stubOnce.Do(func() {
		dir, err := os.MkdirTemp("", "faramir-sops-stub-")
		if err != nil {
			stubErr = err
			return
		}
		out := filepath.Join(dir, "sops")
		cmd := exec.Command("go", "build", "-o", out,
			"github.com/andornaut/faramir/internal/sopstest/stub")
		if combined, err := cmd.CombinedOutput(); err != nil {
			stubErr = err
			t.Logf("building sops stub: %s", combined)
			return
		}
		stubPath = out
	})
	if stubErr != nil {
		t.Skipf("no sops binary and the stub would not build: %v", stubErr)
	}
	return stubPath
}

// DecryptCommand is the [secrets] decrypt_command for a test, pointed at
// whichever sops binary SopsBinary found or built.
func DecryptCommand(t *testing.T) []string {
	t.Helper()
	return []string{SopsBinary(t), "--output-type", "json", "--decrypt", "{file}"}
}
