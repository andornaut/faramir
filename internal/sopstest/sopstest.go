// Package sopstest builds encrypted fixtures and a sops stand-in for tests.
//
// It is imported only from _test.go files.  That is deliberate and load-
// bearing: the sops libraries live here and in ./stub, so they are linked into
// test binaries and never into faramir, faramir-broker, faramir-keeper or
// faramir-exec.  Run "go list -deps ./cmd/..." to confirm.
package sopstest

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	sops "github.com/getsops/sops/v3"
	sopsaes "github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/common"
	sopsformats "github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
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
//
// Encryption needs only the public recipient, which is why the keeper never
// does it: nothing here touches a private identity.
func WriteEncrypted(t *testing.T, path, recipient string, branch sops.TreeBranch) {
	t.Helper()
	mk, err := sopsage.MasterKeyFromRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	tree := sops.Tree{
		Branches: sops.TreeBranches{branch},
		Metadata: sops.Metadata{
			KeyGroups:         []sops.KeyGroup{{mk}},
			Version:           version.Version,
			LastModified:      time.Now().UTC(),
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
		},
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cipher := sopsaes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		t.Fatal(err)
	}
	encMac, err := cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	tree.Metadata.MessageAuthenticationCode = encMac

	store := common.StoreForFormat(sopsformats.Yaml, sopsconfig.NewStoresConfig())
	out, err := store.EmitEncryptedFile(tree)
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
