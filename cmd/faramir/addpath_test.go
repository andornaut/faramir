package main

import (
	"path/filepath"
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
	got, err := newManagedPath(cfg, "prod")
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
			got, err := newManagedPath(cfg, name)
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
	_, err := newManagedPath(cfg, "staging.sops.yml")
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
	if _, err := newManagedPath(&config.Config{}, "prod"); err == nil {
		t.Fatal("a config naming no store accepted a new file")
	}
}
