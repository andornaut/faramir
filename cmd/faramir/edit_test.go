package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/install"
)

// Only a file the config manages: anything else would write a file the broker
// never reads, outside the directory the secrets group protects.
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

// A distinct message, the fix being different: there is nothing to edit.
func TestNoManagedFilesSaysSo(t *testing.T) {
	_, err := resolveManaged(nil, "anything.sops.yml")
	if err == nil {
		t.Fatal("accepted an edit with no managed files")
	}
	if !strings.Contains(err.Error(), "[secrets] files named none") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// Picking one would be picking which credential the operator meant to change.
func TestAnAmbiguousBaseNameIsRefused(t *testing.T) {
	managed := []string{"/opt/a/store.sops.yml", "/opt/b/store.sops.yml"}
	if _, err := resolveManaged(managed, "store.sops.yml"); err == nil {
		t.Error("resolved an ambiguous base name instead of refusing it")
	}
}

// A relative path would resolve through an inherited PATH.
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
	// A root-owned program in a root-owned directory.  Skipped where the host has
	// none.
	installed := ""
	for _, candidate := range append([]string{"/bin/cat", "/usr/bin/cat"}, editors...) {
		if info, err := os.Stat(candidate); err == nil &&
			unsafeToRunAsRoot(candidate, info) == "" {
			installed = candidate
			break
		}
	}
	if installed == "" {
		t.Skip("no root-owned editor on this host to accept")
	}
	got, err := resolveEditor(installed)
	if err != nil || got != installed {
		t.Errorf("resolveEditor(%q) = %q, %v", installed, got, err)
	}
}

// The editor runs as root with the decrypted store open, so a file the operator
// can write is the operator choosing what runs as root.
func TestAnEditorTheOperatorCanWriteIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file below would be root-owned")
	}
	dir := t.TempDir()
	own := filepath.Join(dir, "ed")
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveEditor(own); err == nil {
		t.Error("accepted an editor owned by the account invoking sudo")
	}
	// The directory counts too: write there is permission to replace it.
	if _, err := resolveEditor(filepath.Join(dir, "missing")); err == nil {
		t.Error("accepted an editor in a directory the operator can write")
	}
}

// No candidate may be a wrapper that reads the environment or a dotfile to
// decide what to run, as sensible-editor and /usr/bin/editor do.
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

// Left to config.Load, so the fallback cannot override a variable the caller
// set.
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
	// A socket nothing is listening on, so the unit is what is left and a live
	// install on the host cannot decide this.
	t.Setenv("FARAMIR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	if exists(filepath.Join(install.DefaultConfigDir, "config.toml")) {
		t.Skip("this host has a config at the compiled default")
	}
}

// The path an edit under sudo takes on an install whose config moved out of the
// compiled default.
func TestTheBrokerUnitNamesTheLiveConfig(t *testing.T) {
	want := "/home/op/" + ".config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	if got := resolveConfig(""); got != want {
		t.Errorf("resolveConfig(\"\") = %q, want the path the unit names", got)
	}
}

// A unit naming no config leaves the decision to config.Load.
func TestAUnitWithoutTheVariableFallsThrough(t *testing.T) {
	withUnit(t, "[Service]\nUser=faramir-broker\n")
	if got := resolveConfig(""); got != "" {
		t.Errorf("resolveConfig invented %q from a unit that names no config", got)
	}
}

// A daemon run from a shell finds the install rather than the compiled-in
// default, which is what `faramir broker --check` needs on an install that
// moved.  Under systemd the unit sets FARAMIR_CONFIG and none of this is
// reached; sudo clears it, which is how the check is run.
func TestADaemonTakesTheConfigTheUnitNames(t *testing.T) {
	want := "/home/op/.config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	if got := resolveDaemonConfig(""); got != want {
		t.Errorf("resolveDaemonConfig(\"\") = %q, want the path the unit names", got)
	}
	if got := resolveDaemonConfig("/somewhere/config.toml"); got != "/somewhere/config.toml" {
		t.Errorf("resolveDaemonConfig returned %q for an explicit path", got)
	}
	t.Setenv("FARAMIR_CONFIG", "/from/env/config.toml")
	if got := resolveDaemonConfig(""); got != "" {
		t.Errorf("resolveDaemonConfig returned %q instead of deferring to config.Load", got)
	}
}

// The daemons must not ask the broker which config to load: each is a process
// that may be about to bind that socket, and connecting to it would activate
// the installed daemon and leave the two contending for the path.  A client
// command asks and takes the answer, which is what makes this observable.
func TestADaemonDoesNotAskTheBroker(t *testing.T) {
	live := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(live, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	unit := "/home/op/.config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+unit+"\n")
	t.Setenv("FARAMIR_SOCKET", statusBroker(t, []string{live}))

	if got := resolveConfig(""); got != live {
		t.Errorf("resolveConfig(\"\") = %q, want the running broker's own answer %q", got, live)
	}
	if got := resolveDaemonConfig(""); got != unit {
		t.Errorf("resolveDaemonConfig(\"\") = %q, want the unit's %q: a daemon asked the "+
			"socket it may be about to bind", got, unit)
	}
}

// The recipients come out of the sops metadata block, which is cleartext.  sops
// writes that block in the shape of the file it encrypted, so a managed dotenv
// or ini file spells the same field with "=" and a flattened key.  A regex that
// matched only the YAML and JSON forms reported "names no age recipient" for
// one of those -- after the editor had exited, discarding the edit.
func TestRecipientsOfReadsEverySopsEncoding(t *testing.T) {
	const one = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsdqf6nl"
	const two = "age1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzsdqf6nl"

	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"yaml", "sops:\n    age:\n        - recipient: " + one + "\n", []string{one}},
		{"json", `{"sops":{"age":[{"recipient":"` + one + `"}]}}`, []string{one}},
		{"dotenv", "sops_age__list_0__map_recipient=" + one + "\n", []string{one}},
		{"ini", "[sops]\nage__list_0__map_recipient=" + one + "\n", []string{one}},
		{"two recipients in order", "sops:\n    age:\n        - recipient: " + one +
			"\n        - recipient: " + two + "\n", []string{one, two}},
		{"a repeat is reported once", "recipient: " + one + "\nrecipient: " + one + "\n", []string{one}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret.sops.yml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := recipientsOf(path)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("recipientsOf = %v, want %v", got, tc.want)
			}
		})
	}
}

// A file with no recipient at all is still refused: there is nothing to
// re-encrypt it to.
func TestRecipientsOfRefusesAFileWithNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.sops.yml")
	if err := os.WriteFile(path, []byte("key: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recipientsOf(path); err == nil {
		t.Fatal("a file naming no recipient was accepted")
	}
}
