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
