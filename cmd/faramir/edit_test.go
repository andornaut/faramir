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
	// Compared against the resolved path, not the one asked for: /bin is a
	// symlink to /usr/bin on a merged host, and what runs is the file the links
	// end at.
	want, err := filepath.EvalSymlinks(installed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveEditor(installed)
	if err != nil || got != want {
		t.Errorf("resolveEditor(%q) = %q, %v; want %q", installed, got, err, want)
	}
}

// goodEditor is a root-owned program in root-owned directories, for the tests
// that need one that passes. Empty where the host has none.
func goodEditor(t *testing.T) string {
	t.Helper()
	for _, candidate := range append([]string{"/bin/cat", "/usr/bin/cat"}, editors...) {
		if path, err := checkedEditor(candidate); err == nil {
			return path
		}
	}
	return ""
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
	for _, want := range []string{path, "changed while this was working on it", "again"} {
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

// $VISUAL before $EDITOR, both after --editor, and each held to the same check
// as a path typed on the command line. Honoured rather than ignored because the
// check is what makes a program safe to run as root over the decrypted store:
// an account that cannot write the binary or a directory above it cannot decide
// what runs, whichever source named it.
func TestVisualThenEditorChooseTheEditor(t *testing.T) {
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	t.Setenv("VISUAL", good)
	t.Setenv("EDITOR", "/usr/bin/definitely-not-this")
	if got, err := resolveEditor(""); err != nil || got != good {
		t.Errorf("$VISUAL was not used: resolveEditor(\"\") = %q, %v; want %q", got, err, good)
	}

	// $EDITOR alone is used, and --editor outranks both.
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", good)
	if got, err := resolveEditor(""); err != nil || got != good {
		t.Errorf("$EDITOR was not used: resolveEditor(\"\") = %q, %v; want %q", got, err, good)
	}
	t.Setenv("EDITOR", "/usr/bin/definitely-not-this")
	if got, err := resolveEditor(good); err != nil || got != good {
		t.Errorf("--editor did not outrank $EDITOR: got %q, %v", got, err)
	}
}

// A variable naming something unsafe is refused rather than passed over: it is
// the operator's own setting, and falling through to the list would open the
// store in an editor they did not ask for and say nothing about it.
func TestAnEditorFromTheEnvironmentIsHeldToTheSameCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the file below would be root-owned")
	}
	own := filepath.Join(t.TempDir(), "ed")
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"VISUAL", "EDITOR"} {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "")
		t.Setenv(name, own)
		_, err := resolveEditor("")
		if err == nil {
			t.Errorf("$%s named an editor this account can write and it was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "$"+name) {
			t.Errorf("the refusal does not say $%s named it: %v", name, err)
		}
	}
}

// With nothing naming one, the built-in list decides. This is the stock host:
// sudo's env_reset drops both variables unless the sudoers keep them.
func TestTheBuiltInListIsUsedWhenNothingNamesAnEditor(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	got, err := resolveEditor("")
	if err != nil {
		t.Skipf("this host has none of %v", editors)
	}
	want, err := filepath.EvalSymlinks(got)
	if err != nil || want != got {
		t.Errorf("resolveEditor returned %q, which is not a resolved path", got)
	}
	var found bool
	for _, candidate := range editors {
		if resolved, err := filepath.EvalSymlinks(candidate); err == nil && resolved == got {
			found = true
		}
	}
	if !found {
		t.Errorf("resolveEditor chose %q, which is none of %v", got, editors)
	}
}

// The list is held to the check as well, so no path reaches a root exec
// unexamined. The first that passes wins, not the first that exists.
func TestTheBuiltInListIsHeldToTheCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the file below would be root-owned")
	}
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	writable := filepath.Join(t.TempDir(), "ed")
	if err := os.WriteFile(writable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	restore := editors
	t.Cleanup(func() { editors = restore })
	editors = []string{writable, good}

	if got, err := resolveEditor(""); err != nil || got != good {
		t.Errorf("a candidate this account can write was taken: got %q, %v; want %q",
			got, err, good)
	}

	// And with nothing in the list that passes, the refusal says why rather than
	// reporting that no editor is installed.
	editors = []string{writable}
	_, err := resolveEditor("")
	if err == nil {
		t.Fatal("every candidate failed the check and one was still chosen")
	}
	if !strings.Contains(err.Error(), writable) {
		t.Errorf("the refusal does not name the candidate it turned down: %v", err)
	}
}

// "vim -u /somewhere/vimrc" is an ordinary thing to have in $EDITOR, and -u
// names a file of commands vim runs on startup. Passing arguments through would
// let whoever owns that file decide what root does while every ownership check
// still passed.
func TestAnEditorWithArgumentsIsRefused(t *testing.T) {
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	for _, named := range []string{good + " -u /tmp/evil.vim", good + "\t--cmd :!sh"} {
		if _, err := resolveEditor(named); err == nil {
			t.Errorf("accepted %q, so an argument reached a program running as root", named)
		}
	}
	t.Setenv("VISUAL", good+" -u /tmp/evil.vim")
	if _, err := resolveEditor(""); err == nil {
		t.Error("accepted arguments from $VISUAL")
	}
}

// What is checked has to be what runs. Resolving afterwards would leave the
// links in between deciding it: /usr/bin/vi is an alternatives symlink on a
// Debian host, and the file it names is not the one an ownership check of
// /usr/bin/vi reads.
func TestTheEditorThatRunsIsTheResolvedPath(t *testing.T) {
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	link := filepath.Join(t.TempDir(), "ed")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveEditor(link); err != nil || got != good {
		t.Errorf("resolveEditor(%q) = %q, %v; want the resolved %q", link, got, err, good)
	}
}

// Write on a directory is permission to replace what it holds, and write on
// that directory's parent is permission to replace the directory. So a clean
// file in a clean directory is not enough and the walk runs to /.
func TestEveryDirectoryAboveTheEditorIsChecked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("building a root-owned directory under a loosened one needs root")
	}
	// Not under /tmp: that is 1777 itself, so the walk would stop there and the
	// test would pass without ever reaching the directory it is about.
	//nolint:usetesting // t.TempDir() sits under /tmp, which is the directory
	// this test cannot use.
	base, err := os.MkdirTemp("/root", "faramir-editor-")
	if err != nil {
		t.Skipf("no writable /root on this host: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	mid := filepath.Join(base, "mid")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	ed := filepath.Join(mid, "ed")
	if err := os.WriteFile(ed, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveEditor(ed); err != nil {
		t.Fatalf("a root-owned editor in root-owned directories was refused: %v", err)
	}
	// The file and its own directory are untouched; only the one above them is
	// loosened.
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	err = func() error { _, err := resolveEditor(ed); return err }()
	if err == nil {
		t.Fatal("accepted an editor two levels under a world-writable directory")
	}
	if !strings.Contains(err.Error(), base) {
		t.Errorf("the refusal does not name %s, so the walk stopped short: %v", base, err)
	}
}
