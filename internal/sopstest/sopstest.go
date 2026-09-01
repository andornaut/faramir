// Package sopstest builds encrypted fixtures for tests by running the real
// sops, the same binary the keeper execs. Imported only from _test.go files.
//
// Running it rather than linking it is the point. The keeper execs sops so that
// every cloud KMS SDK sops supports stays out of what installs on a host, and a
// fixture built through the libraries would put the whole set back into the
// module for the tests alone. It also removes the last thing a stand-in could
// get wrong: what these tests are held against is what an operator runs.
//
// A missing sops fails rather than skips. The suites that need one cover
// decryption, re-encryption and how a creation rule is resolved, and a skip
// there is a green run that checked none of it.
package sopstest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"
)

// Branch is a fixture's plaintext: an ordered set of keys, mirroring what a
// YAML document holds. Ordered rather than a map, because a ref's name is its
// path through the document and a test asserts on the order sops emits.
type Branch []Item

// Item is one key and what it holds: a scalar, or a nested Branch.
type Item struct {
	Key   string
	Value any
}

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

// WriteEncrypted builds a sops-encrypted YAML file at path, readable by
// recipient. Only the public recipient is needed; nothing here holds an
// identity.
func WriteEncrypted(t *testing.T, path, recipient string, branch Branch) {
	t.Helper()
	plain := filepath.Join(t.TempDir(), "plain.yaml")
	if err := os.WriteFile(plain, marshal(t, branch), 0o600); err != nil {
		t.Fatal(err)
	}
	// --config names an empty file rather than being left off: without it sops
	// walks up from the plaintext looking for creation rules, and a test that
	// writes a .sops.yaml of its own would have its fixture sealed to whatever
	// that rule says instead of to the recipient asked for here.
	out, err := exec.CommandContext(t.Context(), SopsBinary(t),
		"--config", os.DevNull, "--encrypt", "--age", recipient, plain).Output()
	if err != nil {
		t.Fatalf("sops --encrypt: %v%s", err, stderrOf(err))
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// marshal renders a branch as the YAML sops is handed.
func marshal(t *testing.T, branch Branch) []byte {
	t.Helper()
	out, err := yaml.Marshal(node(t, branch))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// node builds the YAML document, keeping the order the branch was written in.
func node(t *testing.T, value any) *yaml.Node {
	t.Helper()
	branch, ok := value.(Branch)
	if !ok {
		scalar := &yaml.Node{}
		if err := scalar.Encode(value); err != nil {
			t.Fatal(err)
		}
		return scalar
	}
	mapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, item := range branch {
		mapping.Content = append(mapping.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: item.Key},
			node(t, item.Value))
	}
	return mapping
}

// SopsBinary is the sops the test runs, and the one it points the code under
// test at. Absent, the test fails: what these suites cover is how sops itself
// resolves a creation rule and what it emits, and a skip would leave that
// unrun on a green run.
func SopsBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sops")
	if err != nil {
		t.Fatalf("sops is not on PATH, and these tests are held against the real "+
			"binary rather than a stand-in: %v. Install it from "+
			"https://github.com/getsops/sops/releases, or run `make e2e`, which "+
			"fetches a pinned one into tests/e2e", err)
	}
	return path
}

// DecryptCommand is the [secret] decrypt_command for a test, pointed at the
// sops the keeper would exec.
func DecryptCommand(t *testing.T) []string {
	t.Helper()
	return []string{SopsBinary(t), "--output-type", "json", "--decrypt", "{file}"}
}

// stderrOf is what the failing sops wrote, which carries the reason; exec's
// own error is the exit status alone.
func stderrOf(err error) string {
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok || len(exit.Stderr) == 0 {
		return ""
	}
	return ": " + string(exit.Stderr)
}
