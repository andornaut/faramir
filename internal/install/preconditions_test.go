package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The refusal an unadoptable SSH key raises has to name what a repair needs.
// It compares uid AND gid, so a remedy naming only the owner is one an operator
// can carry out in full and still be refused, by a message that then reads "X is
// 0600 broker ... so broker cannot load it".  Both halves for the same reason:
// the public one is checked too, and a remedy naming the private one leaves the
// second run failing on the file the first message never mentioned.
func TestTheSSHKeyRefusalNamesBothHalvesAndTheGroup(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	for _, half := range []string{key, key + ".pub"} {
		if err := os.WriteFile(half, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := &runner{layout: Layout{BrokerUser: "faramir-broker2"}}

	// A uid nothing on this filesystem belongs to, so the check refuses whatever
	// account the test runs as.
	err := run.checkSSHKey(key, 4242, 4242)
	if err == nil {
		t.Fatal("a key owned by another account was accepted")
	}
	says := err.Error()
	for _, want := range []string{
		key,           // the private half
		key + ".pub",  // and the public one, which is checked and used to go unnamed
		"chown ",      // the remedy
		":",           // with a group in it
		"chmod 0600 ", // and the modes the two halves need
		"chmod 0644 ",
	} {
		if !strings.Contains(says, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, says)
		}
	}
	// The specific regression: a remedy that sets the owner and leaves the group.
	if strings.Contains(says, "chown faramir-broker2 ") {
		t.Errorf("the remedy chowns the owner alone, which does not satisfy the "+
			"check that printed it:\n%s", says)
	}
}

// The refusal is printed beside that remedy, so it has to report the same two
// fields the check compares.  owns() itself stays owner-only: the checks that
// compare it are about 0400 and 0600 files, where no group bit is set.
func TestOwnsReportsOwnerAndGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	got := ownsWithGroup(path)
	if !strings.HasPrefix(got, "0640 ") {
		t.Errorf("ownsWithGroup() lost the mode: %q", got)
	}
	if !strings.Contains(strings.TrimPrefix(got, "0640 "), ":") {
		t.Errorf("ownsWithGroup() names no group, so a remedy written from it will "+
			"not satisfy a check that compares one: %q", got)
	}
	if ownsWithGroup(filepath.Join(t.TempDir(), "absent")) != ownsMissing {
		t.Error("an absent file should read as missing")
	}
	// owns() is compared against "%04o account" by the age key and audit log
	// checks, which a group would break on any host whose service accounts do not
	// have same-named primary groups.
	if strings.Contains(strings.TrimPrefix(owns(path), "0640 "), ":") {
		t.Errorf("owns() grew a group, which the checks comparing it do not "+
			"expect: %q", owns(path))
	}
}

// The refusal has to come before anything is handed to the new accounts.  A run
// that stops at the SSH step has already chowned the age key and the audit log,
// and written no unit to match: the daemons keep running as the old uids and the
// host only discovers it at the next restart.
func TestPreconditionsRunBeforeAnythingIsChowned(t *testing.T) {
	var order []string
	for _, step := range (&runner{}).steps() {
		order = append(order, step.name)
	}
	index := func(name string) int {
		for i, step := range order {
			if step == name {
				return i
			}
		}
		t.Fatalf("no step named %q in %v", name, order)
		return -1
	}
	preconditions := index("preconditions")
	for _, destructive := range []string{
		"directories", // chowns the secrets directory to the secrets group
		"age key",     // chowns the key to the keeper
		"config",      // rewrites who the sockets admit
		"ssh key",     // where the refusal used to be raised
		"units",
	} {
		if got := index(destructive); got < preconditions {
			t.Errorf("%s runs at %d, before the preconditions at %d: a refusal then "+
				"leaves a host half moved to accounts whose units were never written",
				destructive, got, preconditions)
		}
	}
}

// Naming a second config directory does not install beside the first: there is
// one set of units, so the daemons move and the old directory is left holding
// its age key and its ciphertext, with its refs no longer redacted.  Refused
// unless the run said so.
func TestAConfigMoveIsRefusedUnlessAskedFor(t *testing.T) {
	dir := t.TempDir()
	systemUnitDir = dir
	t.Cleanup(func() { systemUnitDir = "/etc/systemd/system" })
	unit := "[Service]\nUser=faramir-broker\n" +
		"Environment=FARAMIR_CONFIG=/etc/faramir/config.toml\n"
	if err := os.WriteFile(filepath.Join(dir, "faramir-broker.service"),
		[]byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}

	run := &runner{layout: Layout{ConfigDir: "/opt/faramir2"}}
	err := run.refuseConfigMove()
	if err == nil {
		t.Fatal("a run that moves the daemons to another config directory was allowed")
	}
	for _, want := range []string{"/etc/faramir", "/opt/faramir2", "--move-config"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, err)
		}
	}

	// Consented to: allowed, and still said out loud, what is left behind being
	// key material.
	moving := &runner{layout: Layout{ConfigDir: "/opt/faramir2"},
		opts: Options{MoveConfig: true}}
	if err := moving.refuseConfigMove(); err != nil {
		t.Fatalf("--move-config did not permit the move: %v", err)
	}
	warnings := strings.Join(moving.report.Warnings, "\n")
	for _, want := range []string{"/etc/faramir", "age.key"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("the move warns nothing about %q:\n%s", want, warnings)
		}
	}

	// Provisioning the install this host already has is not a move.
	same := &runner{layout: Layout{ConfigDir: "/etc/faramir"}}
	if err := same.refuseConfigMove(); err != nil {
		t.Errorf("re-provisioning the installed directory was refused: %v", err)
	}
	// Nor is a first install, where no unit names one.
	if err := os.Remove(filepath.Join(dir, "faramir-broker.service")); err != nil {
		t.Fatal(err)
	}
	first := &runner{layout: Layout{ConfigDir: "/opt/faramir2"}}
	if err := first.refuseConfigMove(); err != nil {
		t.Errorf("a first install was refused: %v", err)
	}
}
