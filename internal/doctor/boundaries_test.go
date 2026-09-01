package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
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

func only(t *testing.T, report Report) Finding {
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
			var report Report
			diagnoseSudoCredential(&report, Options{ExecUser: "ex"})
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

// The one boundary check that needs no root is answered without it. Whether
// this host was granted an escalation is a config key rather than something an
// account has to be asked, and it is the commonest reason a brokered `sudo`
// fails: an unprivileged run that said nothing about it left a reader whose
// escalation had just failed with only "some checks need root".
//
// Skipped as root, where diagnoseSudoArrangement answers the same question and
// this path is not reached; the assertion is about what an unprivileged reader
// is told.
func TestAnUnprivilegedRunStillNamesAHostWithNoGrant(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this asserts what a run without root reports")
	}
	var report Report
	diagnoseBoundaries(&report, Options{ExecUser: "ex"}, &config.Config{}, servesUnknown)
	var grant *Finding
	for i, finding := range report.Findings {
		if finding.Name == "sudo grant" {
			grant = &report.Findings[i]
		}
	}
	if grant == nil {
		t.Fatalf("no sudo grant line without root, so nothing says the host was "+
			"never granted one: %+v", report.Findings)
	}
	if grant.Status != StatusNA {
		t.Errorf("status %q, want %q: %s", grant.Status, StatusNA, grant.Detail)
	}
	// The remedy, so the line answers the question a reader arrived with rather
	// than only naming the state.
	if !strings.Contains(grant.Detail, "allow-sudo") {
		t.Errorf("the detail does not name what writes the arrangement: %s", grant.Detail)
	}
}

// Every line is present on a host that granted nothing. A check whose subject
// this install does not have reports n/a rather than vanishing: a line that is
// not there is indistinguishable from one nobody wrote, and one reported ok
// would claim a stack that gates where there is no stack at all.
func TestWithoutAGrantTheSudoChecksReportNotApplicable(t *testing.T) {
	for _, check := range []struct {
		name string
		run  func(*Report)
	}{
		{"sudo grant", func(r *Report) { diagnoseSudoArrangement(r, Options{ExecUser: "ex"}, &config.Config{}) }},
		{"ptrace scope", func(r *Report) { diagnosePtraceScope(r, &config.Config{}) }},
	} {
		t.Run(check.name, func(t *testing.T) {
			var report Report
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
	original := hostlayout.PamDir
	hostlayout.PamDir = dir
	t.Cleanup(func() { hostlayout.PamDir = original })
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

// The environment file and the helper are both part of the arrangement, not
// extras: the sudoers entry names the first as env_file, so a host without it
// makes sudo warn on every brokered command and drops what [command] env
// configured at the sudo, and the second is what the stack's requisite line
// execs, so a host missing it can approve nothing. Each gone is a failure
// naming the file, rather than a silence.
func TestTheSudoGrantCheckReadsEachFileOfTheArrangement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(cfg *config.Config, dir string) string
	}{
		{"the environment file", func(_ *config.Config, dir string) string {
			return filepath.Join(dir, "sudo-env")
		}},
		{"the helper", func(cfg *config.Config, _ string) string {
			return cfg.Sudo.Helper
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, dir := sudoArrangement(t)
			opts := Options{ExecUser: "ex", AgentUser: "op"}

			var whole Report
			diagnoseSudoArrangement(&whole, opts, cfg)
			if got := only(t, whole); got.Status != StatusOK {
				t.Fatalf("status %q, want %q with the whole arrangement in place: %s",
					got.Status, StatusOK, got.Detail)
			}

			// The same host with only that file gone, which is the drift this
			// catches.
			path := tc.remove(cfg, dir)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			var without Report
			diagnoseSudoArrangement(&without, opts, cfg)
			finding := only(t, without)
			if finding.Status != StatusFailed {
				t.Fatalf("status %q, want %q with %s gone: %s",
					finding.Status, StatusFailed, tc.name, finding.Detail)
			}
			if !strings.Contains(finding.Detail, filepath.Base(path)) {
				t.Errorf("the failure does not name the file it is about: %s", finding.Detail)
			}
		})
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
		run  func(*Report)
	}{
		{"sudo grant", func(r *Report) { diagnoseSudoArrangement(r, Options{ExecUser: "ex"}, granted) }},
		{"ptrace scope", func(r *Report) { diagnosePtraceScope(r, granted) }},
	} {
		t.Run(check.name, func(t *testing.T) {
			var report Report
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
	var report Report
	diagnoseSudoGrant(&report, Options{ExecUser: "ex"}, &config.Config{})
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
		{"no [sudo] section, and so no account named", &config.Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report Report
			diagnoseUserns(&report, Options{AgentUser: "op"}, tc.cfg)
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

// An account the liveness probe could not ask as is dropped exactly as an
// unnamed one: a check that would have asked it reports skipped rather than
// claiming its boundary holds on a question nobody could put.
func TestAskableDropsAnAccountNothingCanAskAs(t *testing.T) {
	opts := Options{deadProbers: map[string]bool{"ghost": true}}
	named, skipped := opts.askable("op", "ghost", "")
	if !skipped {
		t.Error("a dead prober did not mark the check skipped")
	}
	if len(named) != 1 || named[0] != "op" {
		t.Errorf("named = %v, want just the askable account", named)
	}
}

// The stack check reads position as well as the helper line: an auth entry
// ahead of it answers before the broker is asked, and requisite below gates
// nothing. Only the sudo-rs branch shape may stand ahead.
func TestPamStackProblemReadsWhatStandsAheadOfTheHelper(t *testing.T) {
	const helperLine = "auth requisite pam_exec.so quiet seteuid /usr/local/libexec/faramir/pam-escalate\n"
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"the rendered service", helperLine +
			"auth optional pam_env.so envfile=/x readenv=1\nauth sufficient pam_permit.so\n", ""},
		{"the sudo-rs block's branch stands ahead",
			"auth [success=ok default=3] pam_succeed_if.so quiet user = faramir-exec\n" + helperLine, ""},
		{"a permit ahead of the helper",
			"auth sufficient pam_permit.so\n" + helperLine, "ahead of the helper"},
		{"an include ahead of the helper",
			"@include common-auth\n" + helperLine, "@include ahead of the helper"},
		{"a sufficient succeed_if ahead is not the branch",
			"auth sufficient pam_succeed_if.so uid >= 0\n" + helperLine, "ahead of the helper"},
		{"requisite matched as a field, not a substring",
			"auth sufficient pam_exec.so quiet seteuid /opt/requisite-tool\n", "not `requisite`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hostsudo.StackProblem(tc.body, "/usr/local/libexec/faramir/pam-escalate")
			if tc.want == "" && got != "" {
				t.Errorf("refused a sound stack: %s", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("problem = %q, want it to say %q", got, tc.want)
			}
		})
	}
}

// A listing that ran names the account whatever it grants; output that does
// not is sudo itself failing, which must not read as no entry. !authenticate
// is the grant's other spelling and never prints NOPASSWD.
func TestNoPasswdEntryTellsAFailedListingFromACleanOne(t *testing.T) {
	for _, tc := range []struct {
		name      string
		out       string
		wantEntry string
		wantKnown bool
	}{
		{"a clean account", "User faramir-exec may run the following commands:\n    (ALL) /usr/bin/id\n", "", true},
		{"a NOPASSWD grant", "User faramir-exec may run:\n    (ALL) NOPASSWD: ALL\n", "(ALL) NOPASSWD: ALL", true},
		{"the !authenticate spelling", "User faramir-exec may run:\n    (ALL) ALL\nDefaults:faramir-exec !authenticate\n", "Defaults:faramir-exec !authenticate", true},
		{"sudo itself failed", "", "", false},
		{"a syntax error", "sudo: parse error in /etc/sudoers.d/broken near line 3\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, known := noPasswdEntry(tc.out, "faramir-exec")
			if known != tc.wantKnown || entry != tc.wantEntry {
				t.Errorf("noPasswdEntry() = (%q, %v), want (%q, %v)", entry, known, tc.wantEntry, tc.wantKnown)
			}
		})
	}
}

// The executor unit cannot set RestrictNamespaces=: it denies clone3(), which is
// how every run is spawned into its cgroup. That leaves a brokered command able
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
	var quiet Report
	diagnoseUserns(&quiet, Options{ExecUser: "faramir-exec"}, &config.Config{})
	if len(quiet.Findings) != 1 || quiet.Findings[0].Status != StatusNA {
		t.Errorf("a host with no sudo grant should report n/a: %v", quiet.Findings)
	}

	granted := &config.Config{}
	granted.Sudo.ExecUser = "faramir-exec"

	var loose Report
	diagnoseUserns(&loose, Options{ExecUser: "faramir-exec"}, granted)
	if len(loose.Findings) != 1 || loose.Findings[0].Status != StatusWarn {
		t.Fatalf("an open switch on a host that grants an escalation: %v", loose.Findings)
	}
	for _, want := range []string{"sysctl -w", "=1", "clone3"} {
		if !strings.Contains(loose.Findings[0].Detail, want) {
			t.Errorf("the finding does not mention %q: %s", want, loose.Findings[0].Detail)
		}
	}

	if err := os.WriteFile(open, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var shut Report
	diagnoseUserns(&shut, Options{ExecUser: "faramir-exec"}, granted)
	if len(shut.Findings) != 1 || shut.Findings[0].Status != StatusOK {
		t.Errorf("a closed switch should read as closed: %v", shut.Findings)
	}
}
