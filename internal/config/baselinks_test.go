package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeBase lays out a base config and drop-ins the way write does, and returns
// the base file's path so a test can read it on its own.
func writeBase(t *testing.T, base string, dropIns map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if dropIns != nil {
		dropInDir := filepath.Join(dir, dropInDirName)
		if err := os.Mkdir(dropInDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range dropIns {
			if err := os.WriteFile(filepath.Join(dropInDir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return path
}

const oneLink = `
[[secrets.link]]
ref = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key = "github.com/oauth_token"
`

func TestBaseLinksReadsTheBaseFile(t *testing.T) {
	path := writeBase(t, minimal+oneLink, nil)
	links, err := BaseLinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Ref != "gh/token" || links[0].Key != "github.com/oauth_token" {
		t.Fatalf("links = %+v", links)
	}
}

// The whole reason this exists.  init renders what BaseLinks returns back into
// config.toml, so a drop-in's link coming back here would be copied into the
// base file and the next load would refuse both as one ref claimed twice.
func TestBaseLinksIgnoresADropIn(t *testing.T) {
	path := writeBase(t, minimal, map[string]string{"10-npm.toml": `
[[secrets.link]]
ref = "npm/token"
path = "/home/operator/.npmrc"
type = "ini"
key = "//registry.npmjs.org/:_authToken"
`})
	links, err := BaseLinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 {
		t.Errorf("links = %+v, want none: that one is the drop-in's", links)
	}
	// And the merged view still has it, so nothing was lost, only attributed.
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets.Links) != 1 {
		t.Errorf("the loaded config lost the drop-in's link: %+v", cfg.Secrets.Links)
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
[[secrets.link]]
ref = "gh/token"
path = "relative/path"
type = "text"
`, nil)
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
