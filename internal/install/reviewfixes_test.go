package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
)

// A drop-in setting Environment=FARAMIR_CONFIG is what the daemons load, and
// uninstall removes <unit>.d directories, so they are a state this install
// expects. Reading the main unit alone sees no move where there is one, and
// lets init re-provision a directory nothing loads.
func TestUnitConfigDirReadsDropIns(t *testing.T) {
	dir := t.TempDir()
	hostunit.SystemUnitDir = dir
	t.Cleanup(func() { hostunit.SystemUnitDir = "/etc/systemd/system" })
	unit := "faramir-broker.service"
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, unit),
		"[Service]\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n")
	if got := hostunit.ConfigDir(unit); got != "/etc/faramir" {
		t.Fatalf("the unit alone: got %q", got)
	}

	// Later drop-ins win, in name order.
	write(filepath.Join(dir, unit+".d", "10-first.conf"),
		"[Service]\nEnvironment=FARAMIR_CONFIG=/srv/one/config.toml\n")
	write(filepath.Join(dir, unit+".d", "20-second.conf"),
		"[Service]\nEnvironment=FARAMIR_CONFIG=/srv/two/config.toml\n")
	if got := hostunit.ConfigDir(unit); got != "/srv/two" {
		t.Errorf("a drop-in overriding the config directory was ignored: got %q", got)
	}

	// And the consequence: init must see that as a move.
	run := &runner{layout: hostlayout.Layout{ConfigDir: "/etc/faramir"}}
	if err := run.refuseRepoint(); err == nil {
		t.Error("re-provisioning /etc/faramir while the daemons load /srv/two was " +
			"allowed, which moves them without saying so")
	}
}

// --dry-run reports and writes nothing, so a move is what it has to report.
// Refusing would make previewing one impossible without consenting to it first.
func TestADryRunPreviewsAConfigMoveInsteadOfRefusingIt(t *testing.T) {
	dir := t.TempDir()
	hostunit.SystemUnitDir = dir
	t.Cleanup(func() { hostunit.SystemUnitDir = "/etc/systemd/system" })
	if err := os.WriteFile(filepath.Join(dir, "faramir-broker.service"),
		[]byte("[Service]\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		layout: hostlayout.Layout{ConfigDir: "/opt/faramir2"},
		opts:   Options{DryRun: true},
	}
	if err := run.refuseRepoint(); err != nil {
		t.Fatalf("a dry run could not preview the move: %v", err)
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	for _, want := range []string{"/etc/faramir", "/opt/faramir2", "--repoint-config"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("the preview does not mention %q:\n%s", want, warnings)
		}
	}
}

// stepSudoGrant needs both /etc/sudoers.d and /etc/pam.d, and skips with a
// warning when either is missing. The precondition has to gate on the same
// pair, or a visudo rejection fails the whole install over a grant that would
// never have been written.
func TestTheSudoersPreconditionGatesOnWhatTheStepNeeds(t *testing.T) {
	layout := sudoGrantLayout(t)
	if !layout.AllowSudo {
		t.Fatal("the fixture is meant to carry the grant")
	}
	dir := t.TempDir()
	realSudoers, realPam := hostlayout.SudoersDir, hostlayout.PamDir
	t.Cleanup(func() { hostlayout.SudoersDir, hostlayout.PamDir = realSudoers, realPam })

	// sudo, no PAM: the grant step skips with a warning, so the precondition must
	// not fail the whole install ahead of it.
	hostlayout.SudoersDir = filepath.Join(dir, "sudoers.d")
	hostlayout.PamDir = filepath.Join(dir, "absent-pam.d")
	if err := os.MkdirAll(hostlayout.SudoersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := &runner{layout: layout}
	if err := run.refuseInvalidSudoers(); err != nil {
		t.Errorf("the precondition failed the install on a host where the grant "+
			"step would have skipped: %v", err)
	}

	// Neither: the same.
	hostlayout.SudoersDir = filepath.Join(dir, "absent-sudoers.d")
	if err := run.refuseInvalidSudoers(); err != nil {
		t.Errorf("the precondition failed the install on a host with no sudo: %v", err)
	}

	// And with no grant asked for, nothing is rendered or judged at all.
	noGrant := &runner{layout: testLayout()}
	if noGrant.layout.AllowSudo {
		t.Fatal("the default fixture is meant to carry no grant")
	}
	if err := noGrant.refuseInvalidSudoers(); err != nil {
		t.Errorf("the precondition ran without --allow-sudo: %v", err)
	}
}
