package vault

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// store is a config naming one managed store in a directory that exists:
// newManagedPath refuses a name under a directory that does not, so the
// directory is what a success-path case needs and the only other field it reads
// is the pattern.
func store(t *testing.T, glob string) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{Secret: config.SecretConfig{
		Patterns: []string{filepath.Join(dir, glob)},
	}}, dir
}

// The stem is what an operator types, so the suffix is added for them.
func TestABareNameIsGivenTheManagedSuffix(t *testing.T) {
	cfg, dir := store(t, "*.sops.yml")
	got, err := NewManagedPath(cfg, "prod")
	if err != nil {
		t.Fatalf("newManagedPath: %v", err)
	}
	if want := filepath.Join(dir, "prod.sops.yml"); got != want {
		t.Errorf("newManagedPath = %q, want %q", got, want)
	}
}

// A name already spelled in full is taken as it stands, whichever managed
// spelling it carries. The second is what a pattern naming .sops.yaml accepts,
// and appending .sops.yml to it would build a name matching nothing.
func TestANameSpelledInFullIsNotDoubled(t *testing.T) {
	for _, name := range []string{"prod.sops.yml", "prod.sops.yaml"} {
		t.Run(name, func(t *testing.T) {
			cfg, dir := store(t, "*"+strings.TrimPrefix(name, "prod"))
			got, err := NewManagedPath(cfg, name)
			if err != nil {
				t.Fatalf("newManagedPath: %v", err)
			}
			if want := filepath.Join(dir, name); got != want {
				t.Errorf("newManagedPath = %q, want %q", got, want)
			}
		})
	}
}

// A name that matches no pattern is refused under the name that was typed. The
// suffix is not appended first: a refusal naming prod.sops.yml.sops.yml sends
// the operator after a file they did not ask for, and the thing to correct is
// either the name or the pattern.
func TestARefusalNamesWhatWasTyped(t *testing.T) {
	cfg, _ := store(t, "*.prod.sops.yml")
	_, err := NewManagedPath(cfg, "staging.sops.yml")
	if err == nil {
		t.Fatal("a name matching no pattern was accepted")
	}
	if strings.Contains(err.Error(), ".sops.yml.sops.yml") {
		t.Errorf("the refusal names a doubled suffix: %v", err)
	}
	if !strings.Contains(err.Error(), "staging.sops.yml") {
		t.Errorf("the refusal does not name what was typed: %v", err)
	}
}

// The store has to be named before anything can be put in it.
func TestNoPatternsIsRefused(t *testing.T) {
	if _, err := NewManagedPath(&config.Config{}, "prod"); err == nil {
		t.Fatal("a config naming no store accepted a new file")
	}
}

// A name that is not a name. Join drops an empty component and a ".", so both
// would build the secrets directory with the suffix glued on and be refused as
// a path matching no pattern: the operator reads a path they never typed and
// has nothing to correct.
func TestANameThatNamesNothingIsRefusedAsThat(t *testing.T) {
	cfg, dir := store(t, "*.sops.yml")
	for _, name := range []string{"", " ", "\t", "."} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			_, err := NewManagedPath(cfg, name)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "name the file") {
				t.Errorf("refusal is %q, want it to ask for a name", err)
			}
			// And it says where one goes, rather than quoting a path built out
			// of nothing.
			if !strings.Contains(err.Error(), dir) {
				t.Errorf("refusal is %q, want it to name %q", err, dir)
			}
			if strings.Contains(err.Error(), dir+".sops.yml") {
				t.Errorf("refusal quotes a path nobody typed: %v", err)
			}
		})
	}
}

// The patterns a refusal quotes are the ones a path is matched against, in
// full. Their file names alone make the refusal read false: "*.sops.yml" is a
// pattern /tmp/outside.sops.yml plainly matches, and what it misses is the
// directory.
func TestARefusalQuotesThePatternsInFull(t *testing.T) {
	cfg, dir := store(t, "*.sops.yml")
	_, err := NewManagedPath(cfg, "/tmp/outside")
	if err == nil {
		t.Fatal("a path outside the store was accepted")
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, "*.sops.yml")) {
		t.Errorf("refusal is %q, want it to quote the whole pattern", err)
	}
}

// A managed file's name is printed back by every command that touches the file
// and typed into every shell command that reaches it, so it is held to bytes
// that can be shown and typed. Refused where it is written rather than escaped
// where it is shown, which would leave an operator with a file they cannot
// name: `vault ls` escaped it and `vault add` printed it raw, so a newline
// split the success line in two and an ESC reached the terminal.
func TestAManagedNameCarriesNoByteATerminalActsOn(t *testing.T) {
	cfg, _ := store(t, "*.sops.yml")
	for _, tc := range []struct{ name, says string }{
		{"two\nlines", "acts on"},
		{"esc\x1b[31mred", "acts on"},
		{"bell\a", "acts on"},
		{"del\x7f", "acts on"},
		{"c1\u009b", "acts on"},
		{"bad\xffbyte", "not valid UTF-8"},
	} {
		t.Run(strconv.Quote(tc.name), func(t *testing.T) {
			_, err := NewManagedPath(cfg, tc.name)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal is %q, want it to say %q", err, tc.says)
			}
		})
	}
	// And an ordinary name, in any script, is still a name.
	for _, name := range []string{"prod", "prod-eu", "prod_1", "\u65e5\u672c\u8a9e", "na\u00efve"} {
		if _, err := NewManagedPath(cfg, name); err != nil {
			t.Errorf("newManagedPath(%q) = %v, want it accepted", name, err)
		}
	}
}
