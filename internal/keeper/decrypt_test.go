package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sopstest"
)

func TestDecryptRoundTrip(t *testing.T) {
	secrets, keys := fixture(t, sopstest.Branch{
		{Key: "router", Value: sopstest.Branch{
			{Key: "admin", Value: "hunter2hunter2"},
		}},
		{Key: "flat", Value: "s3cr3t-value-here"},
		{Key: "enabled", Value: true},
	})

	values, errs, _ := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if got := values["router/admin"]; got != "hunter2hunter2" {
		t.Errorf("router/admin = %q", got)
	}
	if got := values["flat"]; got != "s3cr3t-value-here" {
		t.Errorf("flat = %q", got)
	}
	// "true"/"false" would redact half the output.
	if _, ok := values["enabled"]; ok {
		t.Errorf("boolean leaked into the value set: %v", values)
	}
	for ref := range values {
		if ref == "sops" || strings.HasPrefix(ref, "sops/") {
			t.Errorf("sops metadata leaked into the value set: %s", ref)
		}
	}
}

// The key reaches sops as a path, never as a value. Asserted against a real
// child's environment rather than against the keeper's intent.
func TestTheDecryptChildIsGivenTheKeyPathAndNotTheKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := sopstest.NewIdentity(t, dir)
	managed := filepath.Join(dir, "vault.sops.yaml")
	if err := os.WriteFile(managed, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Dumps what it was handed and answers with an empty tree, so the run
	// succeeds and the environment is what is left to look at.
	dump := filepath.Join(dir, "environ")
	script := filepath.Join(dir, "decrypt")
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\nprintenv > "+dump+"\necho '{}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, errs, _ := DecryptAll(config.SecretConfig{
		Patterns: []string{managed}, DecryptCommand: []string{script, "{file}"},
	}, newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath}))
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}

	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	environ := string(raw)
	if !strings.Contains(environ, "SOPS_AGE_KEY_FILE="+keyPath) {
		t.Errorf("the child was not told where the key is:\n%s", environ)
	}
	for line := range strings.SplitSeq(environ, "\n") {
		if strings.HasPrefix(line, "SOPS_AGE_KEY=") {
			t.Error("KEY MATERIAL IN THE CHILD'S ENVIRONMENT: SOPS_AGE_KEY was set")
		}
	}
	// And the material itself, whatever variable carried it.
	identity, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(identity))
	if !strings.HasPrefix(body, "AGE-SECRET-KEY") {
		t.Fatalf("fixture is not an age identity: %q", body)
	}
	if strings.Contains(environ, body) {
		t.Error("KEY MATERIAL IN THE CHILD'S ENVIRONMENT: the identity itself was passed")
	}
}

// An empty value set means nothing is redacted, so this fails loudly.
func TestWrongIdentityFails(t *testing.T) {
	secrets, _ := fixture(t, sopstest.Branch{{Key: "token", Value: "value-goes-here"}})

	other := t.TempDir()
	wrongKey, _ := sopstest.NewIdentity(t, other)
	keys := newKeyHolder(config.KeeperConfig{AgeKeyFile: wrongKey})

	values, errs, _ := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Fatal("decrypting with the wrong identity reported no error")
	}
	if len(values) != 0 {
		t.Errorf("values were returned anyway: %v", values)
	}
}

func TestOneBadFileDoesNotBlankTheSet(t *testing.T) {
	secrets, keys := fixture(t, sopstest.Branch{{Key: "good", Value: "a-good-value-x"}})
	broken := filepath.Join(t.TempDir(), "broken.sops.yaml")
	if err := os.WriteFile(broken, []byte("not: sops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets.Patterns = append(secrets.Patterns, broken)

	values, errs, _ := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Error("the broken file produced no error")
	}
	if values["good"] != "a-good-value-x" {
		t.Errorf("the good file was lost: %v", values)
	}
}

// twoFiles is a store of two managed files, which is what a shadowed ref needs.
// Patterns names them in a fixed order, so which value wins is the test's to
// decide rather than the filesystem's.
func twoFiles(t *testing.T, first, second sopstest.Branch) (config.SecretConfig, *KeyHolder) {
	t.Helper()
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	firstPath := filepath.Join(dir, "a.sops.yaml")
	secondPath := filepath.Join(dir, "b.sops.yaml")
	sopstest.WriteEncrypted(t, firstPath, recipient, first)
	sopstest.WriteEncrypted(t, secondPath, recipient, second)

	return config.SecretConfig{
			Patterns:       []string{firstPath, secondPath},
			DecryptCommand: sopstest.DecryptCommand(t),
		},
		newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
}

// A ref two files disagree about: one value wins and the other is in no
// redactor, which is a value on this host a command can print in the clear. It
// is reported with both files, the repair being to take the ref out of one.
func TestARefTwoFilesDisagreeAboutIsReported(t *testing.T) {
	secrets, keys := twoFiles(t,
		sopstest.Branch{{Key: "token", Value: "value-from-the-first-file"}},
		sopstest.Branch{{Key: "token", Value: "value-from-the-second-file"}})

	values, errs, shadowed := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if got := values["token"]; got != "value-from-the-second-file" {
		t.Errorf("token = %q, want the last file read to win", got)
	}
	detail, ok := shadowed["token"]
	if !ok {
		t.Fatalf("a ref two files disagree about was not reported: %v", shadowed)
	}
	for _, want := range []string{"a.sops.yaml", "b.sops.yaml"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the report does not name %s, so the repair is not in it: %q", want, detail)
		}
	}
}

// The same ref in two files holding the same value is not shadowed. Nothing is
// lost: the value that does not win is byte for byte the one that does, so it
// is in the redactor and injected by the same ref. Reporting it failed
// `broker --check` and `doctor` on a host with nothing wrong with it.
func TestTheSameValueInTwoFilesIsNotShadowed(t *testing.T) {
	secrets, keys := twoFiles(t,
		sopstest.Branch{{Key: "token", Value: "the-very-same-value-here"}},
		sopstest.Branch{{Key: "token", Value: "the-very-same-value-here"}})

	values, errs, shadowed := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if got := values["token"]; got != "the-very-same-value-here" {
		t.Errorf("token = %q", got)
	}
	if len(shadowed) != 0 {
		t.Errorf("two files holding one value were reported as shadowed: %v", shadowed)
	}
}

// Three files, the middle one agreeing and the last differing: the disagreement
// is found wherever in the read order it falls, and every file that defines the
// ref is named.
func TestADisagreementIsFoundWhereverItFalls(t *testing.T) {
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	written := []string{"same-value-for-this-ref", "same-value-for-this-ref", "a-different-value-here"}
	paths := make([]string, 0, len(written))
	for i, value := range written {
		path := filepath.Join(dir, string(rune('a'+i))+".sops.yaml")
		sopstest.WriteEncrypted(t, path, recipient,
			sopstest.Branch{{Key: "token", Value: value}})
		paths = append(paths, path)
	}
	secrets := config.SecretConfig{Patterns: paths, DecryptCommand: sopstest.DecryptCommand(t)}

	_, errs, shadowed := DecryptAll(secrets, newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath}))
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	detail, ok := shadowed["token"]
	if !ok {
		t.Fatalf("a disagreement in the third file was not reported: %v", shadowed)
	}
	for _, want := range []string{"a.sops.yaml", "b.sops.yaml", "c.sops.yaml"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the report does not name %s: %q", want, detail)
		}
	}
}
