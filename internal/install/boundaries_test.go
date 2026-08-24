package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// answerSudo points the credential check at answers a test wrote, rather than
// at this host's sudoers and shadow.
func answerSudo(t *testing.T, nopasswd string, known bool, shadow string) {
	t.Helper()
	previous := sudoNoPasswd
	sudoNoPasswd = func(string) (string, bool) { return nopasswd, known }
	t.Cleanup(func() { sudoNoPasswd = previous })

	path := filepath.Join(t.TempDir(), "shadow")
	if shadow != "" {
		if err := os.WriteFile(path, []byte(shadow), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousFile := shadowFile
	shadowFile = path
	t.Cleanup(func() { shadowFile = previousFile })
}

func only(t *testing.T, report DoctorReport) Finding {
	t.Helper()
	if len(report.Findings) != 1 {
		t.Fatalf("want one finding, got %d: %+v", len(report.Findings), report.Findings)
	}
	return report.Findings[0]
}

// The credential is checked on every host, a grant or not: a NOPASSWD entry
// skips PAM, which is where the escalation is asked for, so it is a failure
// whether or not this host was installed with --allow-sudo.
//
// A claim that could not be put is a warning rather than a pass: an unread
// shadow file reported as an absent password is a confident answer nobody
// established.
func TestTheSudoCredentialIsCheckedOnEveryHost(t *testing.T) {
	for _, check := range []struct {
		name     string
		nopasswd string
		known    bool
		shadow   string
		want     Status
		unasked  int
	}{
		{name: "locked account, no entry", known: true, shadow: "ex:!:20000::::::\n", want: StatusOK},
		{name: "no password ever set", known: true, shadow: "ex:*:20000::::::\n", want: StatusOK},
		{name: "not in shadow at all", known: true, shadow: "other:!:20000::::::\n", want: StatusOK},
		{
			name: "a NOPASSWD entry", known: true, shadow: "ex:!:20000::::::\n",
			nopasswd: "(ALL) NOPASSWD: ALL", want: StatusFailed,
		},
		{
			name: "a usable password", known: true, shadow: "ex:$y$j9T$abc:20000::::::\n",
			want: StatusFailed,
		},
		{name: "shadow unreadable", known: true, want: StatusWarn, unasked: 1},
		{name: "no account to ask about", known: false, shadow: "ex:!:20000::::::\n",
			want: StatusWarn, unasked: 1},
	} {
		t.Run(check.name, func(t *testing.T) {
			answerSudo(t, check.nopasswd, check.known, check.shadow)
			var report DoctorReport
			diagnoseSudoCredential(&report, DoctorOptions{ExecUser: "ex"})
			finding := only(t, report)
			if finding.Name != "sudo credential" {
				t.Errorf("named %q, want %q", finding.Name, "sudo credential")
			}
			if finding.Status != check.want {
				t.Errorf("status %q, want %q: %s", finding.Status, check.want, finding.Detail)
			}
			if report.NotAsked != check.unasked {
				t.Errorf("counted %d unasked, want %d", report.NotAsked, check.unasked)
			}
		})
	}
}

// Every line is present on a host that granted nothing. A check whose subject
// this install does not have reports n/a rather than vanishing: a line that is
// not there is indistinguishable from one nobody wrote, and one reported ok
// would claim a stack that gates where there is no stack at all.
func TestWithoutAGrantTheSudoChecksReportNotApplicable(t *testing.T) {
	for _, check := range []struct {
		name string
		run  func(*DoctorReport)
	}{
		{"sudo grant", func(r *DoctorReport) { diagnoseSudoArrangement(r, DoctorOptions{ExecUser: "ex"}, &config.Config{}) }},
		{"ptrace scope", func(r *DoctorReport) { diagnosePtraceScope(r, &config.Config{}) }},
	} {
		t.Run(check.name, func(t *testing.T) {
			var report DoctorReport
			check.run(&report)
			finding := only(t, report)
			if finding.Name != check.name {
				t.Errorf("named %q, want %q", finding.Name, check.name)
			}
			if finding.Status != StatusNA {
				t.Errorf("status %q, want %q: %s", finding.Status, StatusNA, finding.Detail)
			}
			// N/a is not a question that went unput, so re-running as root would not
			// answer it and the footer must not say a check is outstanding.
			if report.NotAsked != 0 {
				t.Errorf("counted %d unasked, want 0", report.NotAsked)
			}
			if report.Failed {
				t.Error("n/a failed the report")
			}
		})
	}
}

// sudoArrangement is a granting host as diagnoseSudoArrangement reads one: the
// PAM service, the helper its stack execs, and the environment file the grant
// names beside that helper. Returns the directory the three live in.
func sudoArrangement(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	original := pamDir
	pamDir = dir
	t.Cleanup(func() { pamDir = original })
	// Which sudo this host has decides which arrangement is diagnosed, and the
	// fixture below is the classic one. Pinned rather than probed, or the suite
	// would pass or fail on what the machine running it happens to have installed.
	pinSudo(t, false)

	helper := filepath.Join(dir, "faramir-approve")
	cfg := &config.Config{}
	cfg.Sudo.ExecUser = "ex"
	cfg.Sudo.PamService = "faramir-sudo"
	cfg.Sudo.Helper = helper
	if err := os.WriteFile(filepath.Join(dir, cfg.Sudo.PamService),
		[]byte("auth requisite pam_exec.so seteuid quiet "+helper+"\n"+
			"auth optional pam_env.so envfile="+filepath.Join(dir, "sudo-env")+" readenv=1\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sudo-env"),
		[]byte("FARAMIR_OPERATOR=op\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The helper the stack execs. Named on a requisite line, so a fixture without
	// it is a host where no escalation can be approved rather than a whole
	// arrangement.
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return cfg, dir
}

// The environment file is part of the arrangement, not an extra: the sudoers
// entry names it as env_file, so a host without it makes sudo warn on every
// brokered command and drops what [command] env configured at the sudo. Missing
// is a failure rather than a silence.
func TestTheSudoGrantCheckReadsTheEnvironmentFile(t *testing.T) {
	cfg, dir := sudoArrangement(t)
	opts := DoctorOptions{ExecUser: "ex", AgentUser: "op"}

	var whole DoctorReport
	diagnoseSudoArrangement(&whole, opts, cfg)
	if got := only(t, whole); got.Status != StatusOK {
		t.Fatalf("status %q, want %q with the whole arrangement in place: %s",
			got.Status, StatusOK, got.Detail)
	}

	// The same host with only that file gone, which is the drift this catches.
	if err := os.Remove(filepath.Join(dir, "sudo-env")); err != nil {
		t.Fatal(err)
	}
	var without DoctorReport
	diagnoseSudoArrangement(&without, opts, cfg)
	finding := only(t, without)
	if finding.Status != StatusFailed {
		t.Errorf("status %q, want %q with the environment file gone: %s",
			finding.Status, StatusFailed, finding.Detail)
	}
	if !strings.Contains(finding.Detail, "sudo-env") {
		t.Errorf("the failure does not name the file it is about: %s", finding.Detail)
	}
}

// And on a host that did grant one, the same two checks are answered rather
// than waved through: n/a is about this install's arrangement, not about
// anything doctor could not reach.
func TestWithAGrantTheSameChecksAreAnswered(t *testing.T) {
	granted := &config.Config{}
	granted.Sudo.ExecUser = "ex"
	// A service name no host has: the arrangement check reports the unreadable
	// file, which is an answer about this host rather than a skip.
	granted.Sudo.PamService = "faramir-no-such-service"
	for _, check := range []struct {
		name string
		run  func(*DoctorReport)
	}{
		{"sudo grant", func(r *DoctorReport) { diagnoseSudoArrangement(r, DoctorOptions{ExecUser: "ex"}, granted) }},
		{"ptrace scope", func(r *DoctorReport) { diagnosePtraceScope(r, granted) }},
	} {
		t.Run(check.name, func(t *testing.T) {
			var report DoctorReport
			check.run(&report)
			if finding := only(t, report); finding.Status == StatusNA {
				t.Errorf("reported n/a on a host that granted an escalation: %s", finding.Detail)
			}
		})
	}
}

// The two names carry different claims, so a host that holds a credential is
// still examined for whether its escalation gate works: one is not evidence about
// the other.
func TestTheCredentialAndTheArrangementAreSeparateFindings(t *testing.T) {
	answerSudo(t, "(ALL) NOPASSWD: ALL", true, "ex:!:20000::::::\n")
	var report DoctorReport
	diagnoseSudoGrant(&report, DoctorOptions{ExecUser: "ex"}, &config.Config{})
	if len(report.Findings) != 2 {
		t.Fatalf("want a finding per name, got %+v", report.Findings)
	}
	if got := report.Findings[0]; got.Name != "sudo credential" || got.Status != StatusFailed {
		t.Errorf("first finding is %q %q, want the failed credential", got.Name, got.Status)
	}
	if got := report.Findings[1]; got.Name != "sudo grant" || got.Status != StatusNA {
		t.Errorf("second finding is %q %q, want the arrangement n/a", got.Name, got.Status)
	}
}

// The helper is what the stack's requisite line execs, so a host missing it can
// approve nothing. Checked by this name as well as by installed files: a verdict
// has to be true on its own terms, or an operator reading the grant line alone
// is told the grant works on a host where no escalation can be approved.
func TestTheSudoGrantCheckReadsTheHelper(t *testing.T) {
	cfg, _ := sudoArrangement(t)
	opts := DoctorOptions{ExecUser: "ex", AgentUser: "op"}

	var whole DoctorReport
	diagnoseSudoArrangement(&whole, opts, cfg)
	if got := only(t, whole); got.Status != StatusOK {
		t.Fatalf("status %q, want %q with the whole arrangement in place: %s",
			got.Status, StatusOK, got.Detail)
	}

	if err := os.Remove(cfg.Sudo.Helper); err != nil {
		t.Fatal(err)
	}
	var without DoctorReport
	diagnoseSudoArrangement(&without, opts, cfg)
	finding := only(t, without)
	if finding.Status != StatusFailed {
		t.Fatalf("status %q, want %q with the helper gone: %s",
			finding.Status, StatusFailed, finding.Detail)
	}
	if !strings.Contains(finding.Detail, cfg.Sudo.Helper) {
		t.Errorf("the failure does not name the helper it is about: %s", finding.Detail)
	}
}

// Whether this setting decides anything on this host. Without an escalation
// grant the executor unit carries SystemCallFilter=@system-service, which
// excludes @mount, so a brokered command that unshares a namespace holds
// capabilities with nothing to act on. A host that grants an escalation cannot
// carry that filter, which is what makes the sysctls matter there.
//
// Reported as not applicable rather than as a pass: a pass would say the host
// was checked and found closed, and nothing was read.
func TestUserNamespacesDecideNothingWithoutAnEscalationGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"the config did not load", nil},
		{"no [sudo] section", &config.Config{}},
		{"a [sudo] section naming no account", &config.Config{
			Sudo: config.SudoConfig{},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report DoctorReport
			diagnoseUserns(&report, DoctorOptions{AgentUser: "op"}, tc.cfg)
			got := only(t, report)
			if got.Status != StatusNA {
				t.Errorf("status is %q, want %q: %s", got.Status, StatusNA, got.Detail)
			}
			if !strings.Contains(got.Detail, "@mount") {
				t.Errorf("the detail does not say what the filter excludes: %s", got.Detail)
			}
		})
	}
}
