package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// A drop-in setting Environment=FARAMIR_CONFIG is what the daemons load, and
// uninstall removes <unit>.d directories, so they are a state this install
// expects.  Reading the main unit alone sees no move where there is one, and
// lets init re-provision a directory nothing loads.
func TestUnitConfigDirReadsDropIns(t *testing.T) {
	dir := t.TempDir()
	systemUnitDir = dir
	t.Cleanup(func() { systemUnitDir = "/etc/systemd/system" })
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
	if got := unitConfigDir(unit); got != "/etc/faramir" {
		t.Fatalf("the unit alone: got %q", got)
	}

	// Later drop-ins win, in name order.
	write(filepath.Join(dir, unit+".d", "10-first.conf"),
		"[Service]\nEnvironment=FARAMIR_CONFIG=/srv/one/config.toml\n")
	write(filepath.Join(dir, unit+".d", "20-second.conf"),
		"[Service]\nEnvironment=FARAMIR_CONFIG=/srv/two/config.toml\n")
	if got := unitConfigDir(unit); got != "/srv/two" {
		t.Errorf("a drop-in overriding the config directory was ignored: got %q", got)
	}

	// And the consequence: init must see that as a move.
	run := &runner{layout: Layout{ConfigDir: "/etc/faramir"}}
	if err := run.refuseConfigMove(); err == nil {
		t.Error("re-provisioning /etc/faramir while the daemons load /srv/two was " +
			"allowed, which moves them without saying so")
	}
}

// --dry-run reports and writes nothing, so a move is what it has to report.
// Refusing would make previewing one impossible without consenting to it first.
func TestADryRunPreviewsAConfigMoveInsteadOfRefusingIt(t *testing.T) {
	dir := t.TempDir()
	systemUnitDir = dir
	t.Cleanup(func() { systemUnitDir = "/etc/systemd/system" })
	if err := os.WriteFile(filepath.Join(dir, "faramir-broker.service"),
		[]byte("[Service]\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		layout: Layout{ConfigDir: "/opt/faramir2"},
		opts:   Options{DryRun: true},
	}
	if err := run.refuseConfigMove(); err != nil {
		t.Fatalf("a dry run could not preview the move: %v", err)
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	for _, want := range []string{"/etc/faramir", "/opt/faramir2", "--move-config"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("the preview does not mention %q:\n%s", want, warnings)
		}
	}
}

// stepSudoGrant needs both /etc/sudoers.d and /etc/pam.d, and skips with a
// warning when either is missing.  The precondition has to gate on the same
// pair, or a visudo rejection fails the whole install over a grant that would
// never have been written.
func TestTheSudoersPreconditionGatesOnWhatTheStepNeeds(t *testing.T) {
	layout := sudoGrantLayout(t)
	if !layout.AllowSudo {
		t.Fatal("the fixture is meant to carry the grant")
	}
	dir := t.TempDir()
	realSudoers, realPam := sudoersDir, pamDir
	t.Cleanup(func() { sudoersDir, pamDir = realSudoers, realPam })

	// sudo, no PAM: the grant step skips with a warning, so the precondition must
	// not fail the whole install ahead of it.
	sudoersDir = filepath.Join(dir, "sudoers.d")
	pamDir = filepath.Join(dir, "absent-pam.d")
	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := &runner{layout: layout}
	if err := run.refuseInvalidSudoers(); err != nil {
		t.Errorf("the precondition failed the install on a host where the grant "+
			"step would have skipped: %v", err)
	}

	// Neither: the same.
	sudoersDir = filepath.Join(dir, "absent-sudoers.d")
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

// The executor unit cannot set RestrictNamespaces=: it denies clone3(), which is
// how every run is spawned into its cgroup.  That leaves a brokered command able
// to unshare a user namespace and hold capabilities in it, and nothing applies
// the kernel switch that closes it, so doctor reports it, and only where the
// grant makes it worth acting on.
func TestDiagnoseUsernsReportsWhatTheUnitStoppedBounding(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "apparmor_restrict_unprivileged_userns")
	if err := os.WriteFile(open, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	usernsSwitches = []struct {
		path string
		open string
		shut string
	}{{open, "0", "1"}}
	t.Cleanup(func() {
		usernsSwitches = []struct {
			path string
			open string
			shut string
		}{
			{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "0", "1"},
			{"/proc/sys/kernel/unprivileged_userns_clone", "1", "0"},
		}
	})

	// No grant: the seccomp filter bounds this, so the check has no subject.
	// Reported n/a rather than dropped, like the ptrace scope check beside it: a
	// line that is absent reads the same as one that was never written.
	var quiet DoctorReport
	diagnoseUserns(&quiet, DoctorOptions{ExecUser: "faramir-exec"}, &config.Config{})
	if len(quiet.Findings) != 1 || quiet.Findings[0].Status != StatusNA {
		t.Errorf("a host with no sudo grant should report n/a: %v", quiet.Findings)
	}

	granted := &config.Config{}
	granted.Approval.ExecUser = "faramir-exec"

	var loose DoctorReport
	diagnoseUserns(&loose, DoctorOptions{ExecUser: "faramir-exec"}, granted)
	if len(loose.Findings) != 1 || loose.Findings[0].Status != StatusWarn {
		t.Fatalf("an open switch on a host that grants an approval: %v", loose.Findings)
	}
	for _, want := range []string{"sysctl -w", "=1", "clone3"} {
		if !strings.Contains(loose.Findings[0].Detail, want) {
			t.Errorf("the finding does not mention %q: %s", want, loose.Findings[0].Detail)
		}
	}

	if err := os.WriteFile(open, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var shut DoctorReport
	diagnoseUserns(&shut, DoctorOptions{ExecUser: "faramir-exec"}, granted)
	if len(shut.Findings) != 1 || shut.Findings[0].Status != StatusOK {
		t.Errorf("a closed switch should read as closed: %v", shut.Findings)
	}
}
