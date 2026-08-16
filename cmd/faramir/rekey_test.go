package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	sops "github.com/getsops/sops/v3"

	"github.com/andornaut/faramir/internal/sopstest"
)

// writeRule writes a .sops.yaml naming these recipients, in the shape init
// renders: one creation rule, keys under "- age:".
func writeRule(t *testing.T, dir string, recipients ...string) string {
	t.Helper()
	body := "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    key_groups:\n      - age:\n"
	var bodySb20 strings.Builder
	for _, recipient := range recipients {
		bodySb20.WriteString("          - " + recipient + "\n")
	}
	body += bodySb20.String()
	path := filepath.Join(dir, ".sops.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheRuleRecipientsAreReadInOrder(t *testing.T) {
	dir := t.TempDir()
	first := "age1zvkyg2lc7fyx45ycem9wp2qzcvhhrn6pnhwzcpr0v0y5ea6lyzhs7wcxzn"
	second := "age1dn0q2089z2hrlvlmh7pu8ujn478lehkvw7esqysag0zwea7ffflsd9thv2"
	got, err := ruleRecipients(writeRule(t, dir, first, second, first))
	if err != nil {
		t.Fatal(err)
	}
	// Deduplicated, because a file listing one twice still says one reader.
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Errorf("ruleRecipients = %v, want [%s %s]", got, first, second)
	}
}

// Two rules mean the recipients depend on which path_regex a file matches, and
// reading the whole file cannot answer that.  Refused rather than guessed: a
// guess re-encrypts part of the secrets directory to a set that never governed
// it.
func TestASecondCreationRuleIsRefused(t *testing.T) {
	dir := t.TempDir()
	body := `creation_rules:
  - path_regex: prod/.*\.sops\.ya?ml$
    key_groups:
      - age:
          - age1zvkyg2lc7fyx45ycem9wp2qzcvhhrn6pnhwzcpr0v0y5ea6lyzhs7wcxzn
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1dn0q2089z2hrlvlmh7pu8ujn478lehkvw7esqysag0zwea7ffflsd9thv2
`
	path := filepath.Join(dir, ".sops.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ruleRecipients(path)
	if err == nil {
		t.Fatal("a file with two creation rules was accepted")
	}
	if !strings.Contains(err.Error(), "updatekeys") {
		t.Errorf("the error does not say what to do instead: %v", err)
	}
}

// Re-encrypting to a rule the host's own key is not in produces a secrets
// directory nothing on the machine can open, and re-running cannot undo it.
// Checked before the first file is decrypted.
func TestARuleWithoutTheKeepersKeyIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	stranger := "age1dn0q2089z2hrlvlmh7pu8ujn478lehkvw7esqysag0zwea7ffflsd9thv2"
	if stranger == recipient {
		t.Fatal("the fixture minted the hard-coded key")
	}
	rulePath := writeRule(t, dir, stranger)

	err := keeperStaysAReader(keyPath, []string{stranger}, rulePath)
	if err == nil {
		t.Fatal("a rule leaving out the host's own key was accepted")
	}
	if !strings.Contains(err.Error(), recipient) {
		t.Errorf("the error does not name the key that would be locked out: %v", err)
	}
	if err := keeperStaysAReader(keyPath, []string{stranger, recipient}, rulePath); err != nil {
		t.Errorf("a rule that does list the host's key was refused: %v", err)
	}
}

func TestSameRecipientsIgnoresOrder(t *testing.T) {
	if !sameRecipients([]string{"age1a", "age1b"}, []string{"age1b", "age1a"}) {
		t.Error("the same two keys in a different order read as a change")
	}
	if sameRecipients([]string{"age1a"}, []string{"age1a", "age1b"}) {
		t.Error("an added recipient read as no change")
	}
}

// The point of the command: a file sealed to one key comes out sealed to two,
// still decrypting to the value it held.
func TestARekeyAddsARecipientAndKeepsThePlaintext(t *testing.T) {
	useSops(t)
	dir := t.TempDir()
	keyPath, keeper := sopstest.NewIdentity(t, dir)
	// A second reader, which is what an operator adds to .sops.yaml so a backup of
	// the ciphertext opens without the keeper's key.
	backup, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	extra := backup.Recipient().String()
	store := filepath.Join(dir, "store.sops.yml")
	sopstest.WriteEncrypted(t, store, keeper, sops.TreeBranch{
		{Key: "secret_one", Value: "the-original-value-long-enough"},
	})
	if err := os.Chmod(store, 0o640); err != nil {
		t.Fatal(err)
	}

	if err := reencrypt(store, keyPath, []string{keeper, extra}); err != nil {
		t.Fatalf("reencrypt: %v", err)
	}

	got, err := recipientsOf(store)
	if err != nil {
		t.Fatal(err)
	}
	if !sameRecipients(got, []string{keeper, extra}) {
		t.Errorf("recipients after the rekey = %v, want both %s and %s", got, keeper, extra)
	}
	plain, err := runSops(keyPath, "--decrypt", store)
	if err != nil {
		t.Fatalf("decrypting the result: %v", err)
	}
	if !strings.Contains(string(plain), "the-original-value-long-enough") {
		t.Errorf("the value did not survive the rekey: %s", plain)
	}
	if strings.Contains(got[0], "AGE-SECRET-KEY") {
		t.Error("KEY MATERIAL RETURNED AS A RECIPIENT")
	}
	// The secrets belong to the secrets group after an install, and a rekey that
	// reset the mode would hand it back to whatever the umask said, which is the
	// failure `sops updatekeys` has and this command exists to avoid.
	info, err := os.Stat(store)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode after the rekey is %o, want 640", perm)
	}
}

// A file already sealed to the rule is skipped, and the skip is worth having:
// re-encrypting rewrites the data key even when the recipients are identical,
// so a rekey that did not compare first would make every file in the secrets
// directory look changed to anything watching it.
func TestAnUpToDateFileIsSkippedAndReEncryptingItWouldNotBeFree(t *testing.T) {
	useSops(t)
	dir := t.TempDir()
	keyPath, keeper := sopstest.NewIdentity(t, dir)
	store := filepath.Join(dir, "store.sops.yml")
	sopstest.WriteEncrypted(t, store, keeper, sops.TreeBranch{
		{Key: "secret_one", Value: "the-original-value-long-enough"},
	})
	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}

	// The comparison cmdRekey skips on.
	was, err := recipientsOf(store)
	if err != nil {
		t.Fatal(err)
	}
	if !sameRecipients(was, []string{keeper}) {
		t.Fatalf("recipientsOf = %v, want just %s: an up-to-date file would be "+
			"re-encrypted every run", was, keeper)
	}

	// And what the skip avoids: the same recipients still produce different bytes.
	if err := reencrypt(store, keyPath, []string{keeper}); err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	after, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Error("re-encrypting to the same recipients produced the same bytes, so " +
			"the comparison above saves nothing")
	}
}

// Naming no file is every managed file, which is the case the command exists
// for; naming one that is not managed is refused, so a rekey cannot walk out of
// the secrets directory.
func TestRekeyTargets(t *testing.T) {
	managed := []string{"/etc/faramir/secrets/a.sops.yml", "/etc/faramir/secrets/b.sops.yml"}

	all, err := rekeyTargets(managed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("naming nothing selected %v, want every managed file", all)
	}

	one, err := rekeyTargets(managed, []string{"a.sops.yml", "a.sops.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0] != managed[0] {
		t.Errorf("naming one twice selected %v, want it once", one)
	}

	if _, err := rekeyTargets(managed, []string{"/tmp/elsewhere.sops.yml"}); err == nil {
		t.Error("a path outside the secrets directory was accepted")
	}
	if _, err := rekeyTargets(nil, nil); err == nil {
		t.Error("an empty store was accepted as something to re-key")
	}
}
