package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
)

// refusedAt is the entries a [[secret.block]] would carry for these paths.
func refusedAt(paths ...string) []config.BlockedPath {
	out := make([]config.BlockedPath, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.BlockedPath{Path: path})
	}
	return out
}

// linksAt is the entries a [[secret.link]] would carry for these paths.
func linksAt(paths ...string) []config.Link {
	out := make([]config.Link, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.Link{Ref: "test", Path: path, Type: "text"})
	}
	return out
}

// section is the credentials section an enrolment writes into a tree.
func section(t *testing.T) string {
	t.Helper()
	body, err := agentcfg.CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// touch writes an empty JSON object at rel under home, creating the
// directories above it: the mark that says an agent is in use there.
func touch(t *testing.T, home, rel string) {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeRule writes a .sops.yaml sealing to these recipients.
func writeRule(t *testing.T, path string, recipients ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	body.WriteString("creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    key_groups:\n      - age:\n")
	for _, recipient := range recipients {
		body.WriteString("          - " + recipient + "\n")
	}
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeBlockConfig is an install whose config declares the entries given.
func writeBlockConfig(t *testing.T, entries string) string {
	t.Helper()
	return configDirWith(t, "[command]\ntimeout_sec = 600\n"+entries)
}

// configDirWith is an install directory holding this config.toml, for the
// commands that take a directory and join the file name onto it.
func configDirWith(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
