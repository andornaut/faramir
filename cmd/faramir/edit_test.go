package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/install"
)

// Only a file the config already manages.  A path argument that resolved to
// anything else would write a file the broker never reads, and would take a
// caller outside the one directory the store group protects.
func TestOnlyAManagedFileResolves(t *testing.T) {
	managed := []string{"/opt/store/ansible-ctrl.sops.yml", "/opt/store/home.sops.yml"}

	for _, arg := range []string{
		"/opt/store/ansible-ctrl.sops.yml",  // full path
		"ansible-ctrl.sops.yml",             // base name
		"/opt/store/../store/home.sops.yml", // cleaned to a managed path
	} {
		if _, err := resolveManaged(managed, arg); err != nil {
			t.Errorf("refused a managed file %q: %v", arg, err)
		}
	}

	for _, arg := range []string{
		"/etc/shadow",
		"/opt/store/../../etc/shadow",
		"unmanaged.sops.yml",
		"/opt/store/unmanaged.sops.yml",
	} {
		if got, err := resolveManaged(managed, arg); err == nil {
			t.Errorf("accepted %q, resolving to %q", arg, got)
		}
	}
}

// An empty inventory is a distinct message rather than "not a managed file",
// because the fix is different: there is nothing to edit at all.
func TestNoManagedFilesSaysSo(t *testing.T) {
	_, err := resolveManaged(nil, "anything.sops.yml")
	if err == nil {
		t.Fatal("accepted an edit with no managed files")
	}
	if !strings.Contains(err.Error(), "[secrets] files is empty") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// Two managed files with the same base name have to be named in full.  Picking
// one would be picking which credential the operator meant to change.
func TestAnAmbiguousBaseNameIsRefused(t *testing.T) {
	managed := []string{"/opt/a/store.sops.yml", "/opt/b/store.sops.yml"}
	if _, err := resolveManaged(managed, "store.sops.yml"); err == nil {
		t.Error("resolved an ambiguous base name instead of refusing it")
	}
}

// The editor is a path this process chose.  A relative one would resolve
// through PATH, which is inherited from whoever invoked sudo, so it is refused
// rather than looked up.
func TestARelativeEditorIsRefused(t *testing.T) {
	if _, err := resolveEditor("nano"); err == nil {
		t.Error("accepted a relative editor path")
	}
	if _, err := resolveEditor("../../tmp/evil"); err == nil {
		t.Error("accepted a relative editor path")
	}
}

func TestARequestedEditorMustExist(t *testing.T) {
	if _, err := resolveEditor("/nonexistent/editor"); err == nil {
		t.Error("accepted an editor that is not there")
	}
	real := filepath.Join(t.TempDir(), "ed")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveEditor(real)
	if err != nil || got != real {
		t.Errorf("resolveEditor(%q) = %q, %v", real, got, err)
	}
}

// None of the candidates may be a wrapper that reads the environment or a
// dotfile to decide what to run: sensible-editor and /usr/bin/editor both do,
// and either would hand the choice back to the account this runs on behalf of.
func TestTheCandidateEditorsAreRealEditors(t *testing.T) {
	for _, candidate := range editors {
		if !filepath.IsAbs(candidate) {
			t.Errorf("candidate %q is not absolute", candidate)
		}
		switch filepath.Base(candidate) {
		case "editor", "sensible-editor", "select-editor":
			t.Errorf("candidate %q resolves through operator-writable configuration", candidate)
		}
	}
}

// An explicit --config wins over everything, including the unit.
func TestAnExplicitConfigIsUsedAsGiven(t *testing.T) {
	if got := resolveConfig("/somewhere/config.toml"); got != "/somewhere/config.toml" {
		t.Errorf("resolveConfig returned %q for an explicit path", got)
	}
}

// $FARAMIR_CONFIG is left to config.Load rather than resolved here, so the
// fallback cannot override a variable the caller deliberately set.
func TestAnEnvironmentConfigDefersToLoad(t *testing.T) {
	t.Setenv("FARAMIR_CONFIG", "/from/env/config.toml")
	if got := resolveConfig(""); got != "" {
		t.Errorf("resolveConfig returned %q instead of deferring to config.Load", got)
	}
}

// withUnit points the fallback at a fixture and restores it afterwards.
func withUnit(t *testing.T, body string) {
	t.Helper()
	unit := filepath.Join(t.TempDir(), "faramir-broker.service")
	if err := os.WriteFile(unit, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	original := brokerUnit
	brokerUnit = unit
	t.Cleanup(func() { brokerUnit = original })
	t.Setenv("FARAMIR_CONFIG", "")
	// Pointed at a socket nothing is listening on, so the broker cannot answer
	// and the unit is what is left.  Without this the test would pass or fail
	// depending on whether the host running it has a live install.
	t.Setenv("FARAMIR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	if exists(filepath.Join(install.DefaultConfigDir, "config.toml")) {
		t.Skip("this host has a config at the compiled default")
	}
}

// With nothing else naming a config, the broker's unit says which one is live.
// This is the path an edit under sudo actually takes on an install whose config
// moved out of the compiled default.
func TestTheBrokerUnitNamesTheLiveConfig(t *testing.T) {
	want := "/home/op/" + ".faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	if got := resolveConfig(""); got != want {
		t.Errorf("resolveConfig(\"\") = %q, want the path the unit names", got)
	}
}

// A unit that names no config leaves the decision to config.Load rather than
// inventing a path.
func TestAUnitWithoutTheVariableFallsThrough(t *testing.T) {
	withUnit(t, "[Service]\nUser=faramir-broker\n")
	if got := resolveConfig(""); got != "" {
		t.Errorf("resolveConfig invented %q from a unit that names no config", got)
	}
}
