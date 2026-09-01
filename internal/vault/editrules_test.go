package vault

// Which creation rules `faramir vault edit` and `faramir reader reseal` encrypt under.
//
// Against the host's sops, and skipped without one: what is asserted here is
// how sops resolves .sops.yaml and matches path_regex, which the stand-in does
// not model, so running these against it would assert nothing and report a
// pass.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sops "github.com/getsops/sops/v3"

	"github.com/andornaut/faramir/internal/sopstest"
)

func requireRealSops(t *testing.T) {
	t.Helper()
	installed, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("this asserts how sops reads creation rules; the stand-in has none")
	}
	previous := sopsBinary
	sopsBinary = installed
	t.Cleanup(func() { sopsBinary = previous })
}

// managedFixture is an install's shape: a rule file with the secrets in a
// directory beneath it, which is what decides the path sops matches a rule
// against.
type managedFixture struct {
	store     string
	keyPath   string
	rulePath  string
	recipient string
}

func newManagedFixture(t *testing.T) managedFixture {
	t.Helper()
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	f := managedFixture{
		store:     filepath.Join(dir, "secrets", "store.sops.yml"),
		keyPath:   keyPath,
		rulePath:  filepath.Join(dir, ".sops.yaml"),
		recipient: recipient,
	}
	sopstest.WriteEncrypted(t, f.store, recipient, sops.TreeBranch{
		{Key: "secret_one", Value: "the-original-value-long-enough"},
	})
	f.writeRule(t, `\.sops\.ya?ml$`, "")
	return f
}

func (f managedFixture) writeRule(t *testing.T, pathRegex, extra string) {
	t.Helper()
	rule := "creation_rules:\n  - path_regex: " + pathRegex + "\n" + extra +
		"    key_groups:\n      - age:\n          - " + f.recipient + "\n"
	if err := os.WriteFile(f.rulePath, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
}

// edit runs one edit that rewrites the stored value, and returns the file after.
func (f managedFixture) edit(t *testing.T, to string) ([]byte, error) {
	t.Helper()
	editor := editorScript(t, `sed -i 's/the-original-value-long-enough/`+to+`/' "$1"`)
	if _, err := Edit(f.keyPath, f.rulePath, editor, f.store); err != nil {
		return nil, err
	}
	after, err := os.ReadFile(f.store)
	if err != nil {
		t.Fatal(err)
	}
	return after, nil
}

// sops resolves .sops.yaml by walking up from the process's working directory,
// and for these commands that is wherever the operator was standing: very often
// an enrolled working tree, which the coding agent writes. A rule found there
// must not decide how the managed file is written, or an 'unencrypted_regex' in
// it puts the values it names into that file in cleartext.
func TestACreationRuleInTheWorkingDirectoryIsNotRead(t *testing.T) {
	requireRealSops(t)
	f := newManagedFixture(t)

	planted := t.TempDir()
	if err := os.WriteFile(filepath.Join(planted, ".sops.yaml"), []byte(
		"creation_rules:\n  - path_regex: .*\n"+
			"    unencrypted_regex: '^(secret_one)$'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(planted)

	after, err := f.edit(t, "a-replacement-value-long-enough")
	if err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	if strings.Contains(string(after), "a-replacement-value-long-enough") {
		t.Errorf("a creation rule in the working directory left the value in "+
			"cleartext in the managed file:\n%s", after)
	}
}

// sops matches path_regex against the file's path relative to the rule file, so
// on an install the rule is judged against "secrets/store.sops.yml". The
// plaintext is encrypted from a copy in a tmpfs, which is nowhere near the rule
// file, so without --filename-override the rule is matched against the tmpfs
// path instead and one naming where the secrets live matches nothing: every
// edit would end in "no matching creation rules found".
func TestARulePinnedToTheSecretsDirectoryStillEncrypts(t *testing.T) {
	requireRealSops(t)
	f := newManagedFixture(t)
	f.writeRule(t, `^secrets/.*\.sops\.yml$`, "")

	after, err := f.edit(t, "another-value-long-enough-here")
	if err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	if strings.Contains(string(after), "another-value-long-enough-here") {
		t.Errorf("the new value is in the file as plaintext:\n%s", after)
	}
	if !strings.Contains(string(after), "sops") {
		t.Errorf("the rewritten file does not look like a sops file:\n%s", after)
	}
}

// sops refuses a file no creation rule covers, and it refuses it at the
// encrypt, which is after the editor has run. So the question is put first: an
// edit that cannot be written back has to be refused while there is nothing to
// lose, not after the operator has typed.
func TestAnEditNoRuleCoversIsRefusedBeforeTheEditor(t *testing.T) {
	requireRealSops(t)
	f := newManagedFixture(t)
	f.writeRule(t, `^elsewhere/.*\.sops\.yml$`, "")

	ran := filepath.Join(t.TempDir(), "ran")
	editor := editorScript(t, `touch `+ran)
	if _, err := Edit(f.keyPath, f.rulePath, editor, f.store); err == nil {
		t.Fatal("an edit no rule covers was accepted")
	} else if !strings.Contains(err.Error(), "no creation rule matching") {
		t.Errorf("the error does not name the cause: %v", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("the editor ran, so the operator typed into an edit that was going " +
			"to be thrown away")
	}
}

// The refusal reseal already makes. sops takes a shamir rule with one key group
// without complaint and writes the threshold beside it, so the file still opens
// afterwards, with any single one of the keys the split existed to keep apart.
func TestAnEditUnderASplitKeyIsRefused(t *testing.T) {
	f := newManagedFixture(t)
	rule := "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n" +
		"    shamir_threshold: 2\n" +
		"    key_groups:\n      - age:\n          - " + f.recipient +
		"\n      - age:\n          - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"
	if err := os.WriteFile(f.rulePath, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ruleMustCover(f.rulePath, f.store, []string{f.recipient})
	if err == nil {
		t.Fatal("an edit under a split data key was accepted")
	}
	if !strings.Contains(err.Error(), "shamir_threshold") {
		t.Errorf("the error does not name the cause: %v", err)
	}
}

// A probe that cannot be put is not a refusal: what is being ruled out is the
// case certain to fail later, and taking the command away over a question
// nobody could answer would be worse than the failure it avoids.
func TestAnUnaskableRuleCheckDoesNotRefuseTheEdit(t *testing.T) {
	f := newManagedFixture(t)
	previous := sopsBinary
	sopsBinary = filepath.Join(t.TempDir(), "no-sops-here")
	t.Cleanup(func() { sopsBinary = previous })

	if err := ruleMustCover(f.rulePath, f.store, []string{f.recipient}); err != nil {
		t.Errorf("an edit was refused because the probe could not be run: %v", err)
	}
}

// A host with no .sops.yaml encrypts with sops' defaults, which cover every
// file, so there is no rule to match and nothing to refuse.
func TestNoRuleFileMeansNothingToCover(t *testing.T) {
	f := newManagedFixture(t)
	if err := os.Remove(f.rulePath); err != nil {
		t.Fatal(err)
	}
	if err := ruleMustCover(f.rulePath, f.store, []string{f.recipient}); err != nil {
		t.Errorf("an edit was refused on a host that has no creation rules: %v", err)
	}
}

// The rule the install names is the one that decides the shape of what is
// written back, which is what makes an operator's own setting hold across an
// edit rather than being replaced by sops' defaults.
func TestTheInstallsOwnRuleDecidesWhatIsEncrypted(t *testing.T) {
	requireRealSops(t)
	f := newManagedFixture(t)
	f.writeRule(t, `\.sops\.ya?ml$`, "    unencrypted_regex: '^(secret_one)$'\n")

	after, err := f.edit(t, "left-in-the-clear-on-purpose")
	if err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	if !strings.Contains(string(after), "left-in-the-clear-on-purpose") {
		t.Errorf("the rule asked for this key to stay unencrypted and it did not:\n%s", after)
	}
}

// A host whose .sops.yaml has been removed still has files to open: sops
// refuses to start on a config path it cannot read, decrypt included, so an
// absent rule has to become no rule rather than a path.
func TestAnAbsentRuleFileIsNoRuleRatherThanAMissingOne(t *testing.T) {
	if got := sopsConfigPath(filepath.Join(t.TempDir(), "gone.yaml")); got != os.DevNull {
		t.Errorf("sopsConfigPath for an absent rule = %q, want %q", got, os.DevNull)
	}
	if got := sopsConfigPath(""); got != os.DevNull {
		t.Errorf("sopsConfigPath for no rule = %q, want %q", got, os.DevNull)
	}
	dir := t.TempDir()
	rule := filepath.Join(dir, ".sops.yaml")
	if err := os.WriteFile(rule, []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := sopsConfigPath(rule); got != rule {
		t.Errorf("sopsConfigPath for a rule that is there = %q, want %q", got, rule)
	}
}
