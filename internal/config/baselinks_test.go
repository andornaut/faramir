package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeBase lays out a config file and returns its path, for the readers that
// take one rather than a loaded config.
func writeBase(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const oneLink = `
[[secret.link]]
ref = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key = "github.com/oauth_token"
`

func TestBaseLinksReadsTheFile(t *testing.T) {
	links, err := BaseLinks(writeBase(t, minimal+oneLink))
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Ref != "gh/token" || links[0].Key != "github.com/oauth_token" {
		t.Fatalf("links = %+v", links)
	}
}

// A first install: the file is not there and that is not an error.
func TestBaseLinksOnAMissingFile(t *testing.T) {
	links, err := BaseLinks(filepath.Join(t.TempDir(), "config.toml"))
	if err != nil {
		t.Fatalf("a missing config was an error: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("links = %+v", links)
	}
}

// Held to the same rules the loader applies, so a hand-edited entry is refused
// here rather than at the next daemon start.
func TestBaseLinksValidates(t *testing.T) {
	path := writeBase(t, minimal+`
[[secret.link]]
ref = "gh/token"
path = "relative/path"
type = "text"
`)
	if _, err := BaseLinks(path); err == nil {
		t.Fatal("a relative path was accepted")
	}
}

func TestValidateLink(t *testing.T) {
	ok := Link{Ref: "gh/token", Path: "/x", Type: "yaml", Key: "a/b"}
	if err := ValidateLink(ok); err != nil {
		t.Errorf("a good link was refused: %v", err)
	}
	if err := ValidateLink(Link{Ref: "gh/token", Path: "/x", Type: "text", Key: "a"}); err == nil {
		t.Error("a key on a whole-file type was accepted")
	}
}

// Derived, not configured: the store is where the config is, and the three
// extensions are the three the agent deny rules already refuse.
func TestTheStoreIsDerivedFromWhereTheConfigSits(t *testing.T) {
	path := writeBase(t, minimal)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(path), "secrets")
	// One, not the three sops can read: faramir writes the store, so a second
	// spelling would be a second way for a file to be named and nothing gained.
	want := []string{filepath.Join(dir, "*.sops.yml")}
	if len(cfg.Secret.Patterns) != len(want) {
		t.Fatalf("patterns = %v, want %v", cfg.Secret.Patterns, want)
	}
	for i, pattern := range want {
		if cfg.Secret.Patterns[i] != pattern {
			t.Errorf("patterns[%d] = %q, want %q", i, cfg.Secret.Patterns[i], pattern)
		}
	}
}

// No key names the store or how it is decrypted, so a file cannot point either
// somewhere else.
func TestTheStoreAndTheDecryptCommandAreNotKeys(t *testing.T) {
	for _, body := range []string{
		"\n[secret]\npatterns = [\"/srv/other/*.sops.yml\"]\n",
		"\n[secret]\ndecrypt_command = [\"cat\"]\n",
	} {
		if _, err := Load(writeBase(t, minimal+body)); err == nil {
			t.Errorf("accepted a config setting it: %s", body)
		}
	}
}
