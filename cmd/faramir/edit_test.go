package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/sopsrule"
)

// Only a file the config manages: anything else would write a file the broker
// never reads, outside the directory the secrets group protects.
func TestOnlyAManagedFileResolves(t *testing.T) {
	managed := []string{"/opt/store/ansible.sops.yml", "/opt/store/home.sops.yml"}

	for _, arg := range []string{
		"/opt/store/ansible.sops.yml",       // full path
		"ansible.sops.yml",                  // base name
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
	if !strings.Contains(err.Error(), "the managed store named none") {
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
	// A root-owned program in a root-owned directory. Skipped where the host has
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

// The variable wins over a running broker, which is what makes it the way out
// for a host whose install the broker cannot be asked about.
func TestAnEnvironmentConfigWins(t *testing.T) {
	t.Setenv("FARAMIR_CONFIG", "/from/env/config.toml")
	got, err := findConfigFile(status{configDir: "/etc/faramir"})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != "/from/env/config.toml" {
		t.Errorf("findConfigFile = %q, want the path the variable names", got)
	}
}

// It names the config file. A directory is refused rather than read as one, or
// FARAMIR_CONFIG=/etc/faramir would make the install /etc.
func TestAnEnvironmentConfigNamingADirectoryIsRefused(t *testing.T) {
	t.Setenv("FARAMIR_CONFIG", t.TempDir())
	if got, err := findConfigFile(status{}); err == nil {
		t.Errorf("a directory resolved to %q instead of being refused", got)
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
}

// The path an edit under sudo takes on an install whose config moved out of the
// compiled default.
func TestTheBrokerUnitNamesTheLiveConfig(t *testing.T) {
	want := "/home/op/" + ".config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	got, err := findConfigFile(askBroker(socketDefault()))
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != want {
		t.Errorf("findConfigFile = %q, want the path the unit names", got)
	}
}

// A unit naming no config is a host nothing can be asked about: no broker
// answering and no unit naming a file is not the compiled-in default, it is an
// install this command cannot find.
func TestAUnitWithoutTheVariableIsAnError(t *testing.T) {
	withUnit(t, "[Service]\nUser=faramir-broker\n")
	if got, err := findConfigFile(askBroker(socketDefault())); err == nil {
		t.Errorf("findConfigFile invented %q from a unit that names no config", got)
	}
}

// A daemon run from a shell finds the install rather than the compiled-in
// default, which is what `faramir broker --check` needs on an install that
// moved. Under systemd the unit sets FARAMIR_CONFIG and none of this is
// reached; sudo clears it, which is how the check is run.
func TestADaemonTakesTheConfigTheUnitNames(t *testing.T) {
	want := "/home/op/.config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	got, err := findConfigFile(status{})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != want {
		t.Errorf("the daemon ladder = %q, want the path the unit names", got)
	}
	t.Setenv("FARAMIR_CONFIG", "/from/env/config.toml")
	got, err = findConfigFile(status{})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != "/from/env/config.toml" {
		t.Errorf("the daemon ladder = %q, want the path the variable names", got)
	}
}

// The daemons must not ask the broker which config to load: each is a process
// that may be about to bind that socket, and connecting to it would activate
// the installed daemon and leave the two contending for the path. A client
// command asks and takes the answer, which is what makes this observable.
func TestADaemonDoesNotAskTheBroker(t *testing.T) {
	live := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(live, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	unit := "/home/op/.config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+unit+"\n")
	t.Setenv("FARAMIR_SOCKET", statusBroker(t, live))

	got, err := findConfigFile(askBroker(socketDefault()))
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != live {
		t.Errorf("the client ladder = %q, want the running broker's own answer %q", got, live)
	}
	got, err = findConfigFile(status{})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != unit {
		t.Errorf("the daemon ladder = %q, want the unit's %q: a daemon asked the "+
			"socket it may be about to bind", got, unit)
	}
}

// The recipients come out of the sops metadata block, which is cleartext. sops
// writes that block in the shape of the file it encrypted, so a managed dotenv
// or ini file spells the same field with "=" and a flattened key. Every shape
// has to be read: an unrecognised one reports "names no age recipient" after the
// editor has exited, which discards the edit.
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
			got, err := sopsrule.SealedTo(path)
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
	if _, err := sopsrule.SealedTo(path); err == nil {
		t.Fatal("a file naming no recipient was accepted")
	}
}

// Two edits of one managed file each decrypt their own copy. Whichever encrypts
// last would otherwise replace the other's work with a copy that never had it,
// and both would report the file written: a secret an operator had just saved,
// gone, with nothing said.
func TestAnEditIsRefusedWhenTheFileMovedUnderIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.sops.yml")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := digestOf(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := unchangedSince(path, before); err != nil {
		t.Errorf("a file nothing touched was refused: %v", err)
	}

	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = unchangedSince(path, before)
	if err == nil {
		t.Fatal("a file something else wrote was accepted")
	}
	for _, want := range []string{path, "changed while the editor was open", "again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}

	// Same bytes written again is the same file: an editor that rewrites without
	// changing anything must not read as somebody else's write.
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unchangedSince(path, before); err != nil {
		t.Errorf("identical contents were refused: %v", err)
	}
}
