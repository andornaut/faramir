package main

// --dry-run and --json on the edit commands: what a configuration manager's
// check mode runs, and the document it parses.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/testio"
)

const (
	recipientOne = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsdqf6nl"
	recipientTwo = "age1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzsdqf6nl"
)

// Every idempotent edit takes both flags, so a configuration manager can run any
// of them in check mode and parse what it says. `vault edit` is interactive and
// has no place in a converge.
func TestEveryEditCommandTakesDryRunAndJSON(t *testing.T) {
	root := newRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	for _, path := range [][]string{
		{"init"}, {"enrol"}, {"unenrol"},
		{"block", "add"}, {"block", "rm"},
		{"link", "add"}, {"link", "rm"},
		{"reader", "add"}, {"reader", "rm"}, {"reader", "reseal"},
		{"vault", "add"}, {"vault", "rm"},
	} {
		name := strings.Join(path, " ")
		c, _, err := root.Find(path)
		if err != nil || c.Name() != path[len(path)-1] {
			t.Errorf("%s: no such command: %v", name, err)
			continue
		}
		for _, flag := range []string{"dry-run", "json"} {
			if c.Flags().Lookup(flag) == nil {
				t.Errorf("%s has no --%s", name, flag)
			}
		}
	}
}

// storeDocument is the part of the --json document these tests read.
type storeDocument struct {
	Changed bool `json:"changed"`
	DryRun  bool `json:"dry_run"`
	Steps   []struct {
		Name    string `json:"step"`
		Changed bool   `json:"changed"`
		Detail  string `json:"detail"`
	} `json:"steps"`
	Version string `json:"version"`
}

func parseStoreDocument(t *testing.T, out string) storeDocument {
	t.Helper()
	var doc storeDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not the document: %v\n%s", err, out)
	}
	return doc
}

// sealedFixture is a managed file sealed to one recipient, as far as reading its
// recipients goes: the sops metadata block is cleartext.
func sealedFixture(t *testing.T, recipient string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.sops.yml")
	body := "token: ENC[AES256_GCM,data:synthetic]\nsops:\n    age:\n        - recipient: " +
		recipient + "\n"
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

// A dry-run reseal reports the file it would re-encrypt and leaves it as it
// was, in both forms: a line on stderr, or a changed step in the document.
func TestADryRunResealReportsTheChangeAndWritesNothing(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		target := sealedFixture(t, recipientOne)
		before, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		store := &storeContext{cfg: &config.Config{}, targets: []string{target}}
		edit := newStoreEdit(true, asJSON)

		var stdout string
		stderr, code := testio.CaptureStderr(t, func() int {
			var code int
			stdout, code = testio.CaptureStdout(t, func() int {
				return edit.done("reader reseal",
					resealStore("reader reseal", edit, store, []string{recipientTwo}))
			})
			return code
		})

		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr: %s", code, stderr)
		}
		if after, err := os.ReadFile(target); err != nil || string(after) != string(before) {
			t.Errorf("a dry run rewrote %s", target)
		}
		if !asJSON {
			if !strings.Contains(stderr, "would re-encrypt "+target) {
				t.Errorf("stderr does not name the file it would re-encrypt: %q", stderr)
			}
			if stdout != "" {
				t.Errorf("printed a document without --json: %q", stdout)
			}
			continue
		}
		if strings.Contains(stderr, "would re-encrypt") {
			t.Errorf("--json also printed the outcome lines: %q", stderr)
		}
		doc := parseStoreDocument(t, stdout)
		if !doc.Changed || !doc.DryRun || len(doc.Steps) != 1 ||
			doc.Steps[0].Name != stepReseal || !doc.Steps[0].Changed || doc.Steps[0].Detail != target {
			t.Errorf("document = %+v, want one changed reseal step for %s", doc, target)
		}
	}
}

// A file already sealed to the rule is a step that changed nothing, so the
// document says the store is as it should be rather than saying nothing.
func TestAResealOfASealedStoreReportsNoChange(t *testing.T) {
	target := sealedFixture(t, recipientOne)
	store := &storeContext{cfg: &config.Config{}, targets: []string{target}}
	edit := newStoreEdit(true, true)

	stdout, code := testio.CaptureStdout(t, func() int {
		return edit.done("reader reseal",
			resealStore("reader reseal", edit, store, []string{recipientOne}))
	})

	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	doc := parseStoreDocument(t, stdout)
	if doc.Changed || len(doc.Steps) != 1 || doc.Steps[0].Changed {
		t.Errorf("document = %+v, want one unchanged step", doc)
	}
}

// A dry-run removal inspects the file a real one would, asks nothing, and
// removes nothing.
func TestADryRunVaultRemovalReportsTheChangeAndRemovesNothing(t *testing.T) {
	target := sealedFixture(t, recipientOne)
	edit := newStoreEdit(true, true)

	stdout, code := testio.CaptureStdout(t, func() int {
		return previewRemoval("vault rm", edit, target)
	})

	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("a dry run removed %s: %v", target, err)
	}
	doc := parseStoreDocument(t, stdout)
	if !doc.Changed || !doc.DryRun || len(doc.Steps) != 1 ||
		doc.Steps[0].Name != stepManagedFile || doc.Steps[0].Detail != target {
		t.Errorf("document = %+v, want one changed step for %s", doc, target)
	}

	// And a file a real run would refuse is refused, with no document.
	gone := filepath.Join(t.TempDir(), "gone.sops.yml")
	stdout, code = testio.CaptureStdout(t, func() int {
		_, refused := testio.CaptureStderr(t, func() int {
			return previewRemoval("vault rm", newStoreEdit(true, true), gone)
		})
		return refused
	})
	if code != 1 || stdout != "" {
		t.Errorf("a missing file: exit %d, stdout %q, want 1 and nothing", code, stdout)
	}
}

// A dry-run add asks the rule what a real add asks it before the editor
// opens, and creates nothing.
func TestADryRunVaultAddChecksTheRuleAndCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, ".sops.yaml")
	rule := "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    age: " + recipientOne + "\n"
	if err := os.WriteFile(rulePath, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "secrets", "app.sops.yml")
	edit := newStoreEdit(true, true)

	stdout, code := testio.CaptureStdout(t, func() int {
		return previewAdd("vault add", edit, rulePath, target)
	})

	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("a dry run created %s: %v", target, err)
	}
	doc := parseStoreDocument(t, stdout)
	if !doc.Changed || !doc.DryRun || len(doc.Steps) != 1 ||
		doc.Steps[0].Name != stepManagedFile || doc.Steps[0].Detail != target {
		t.Errorf("document = %+v, want one changed step for %s", doc, target)
	}

	// A rule that is not there fails the real add, so it fails the preview.
	stdout, code = testio.CaptureStdout(t, func() int {
		_, refused := testio.CaptureStderr(t, func() int {
			return previewAdd("vault add", newStoreEdit(true, true),
				filepath.Join(dir, "missing.yaml"), target)
		})
		return refused
	})
	if code != 1 || stdout != "" {
		t.Errorf("a missing rule: exit %d, stdout %q, want 1 and nothing", code, stdout)
	}
}
