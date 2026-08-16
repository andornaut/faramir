package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/version"
)

// sops takes the first .sops.yaml walking up from the working directory, so a
// copy in the secrets directory shadows the one above it.  Each of the four
// states reads differently, the remedies being different: compare recipients
// and delete one, or move it.  No systemd, accounts or root needed.
func TestDiagnoseSopsConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current bool
		stale   bool
		want    Status
		says    []string
	}{
		{
			name: "the rule where it belongs", current: true,
			want: StatusOK, says: []string{"/.sops.yaml"},
		},
		{
			name: "a copy in the secrets directory shadows it", current: true, stale: true,
			want: StatusWarn, says: []string{"shadows", "recipients", "rm "},
		},
		{
			name: "only the copy earlier installs left behind", stale: true,
			want: StatusWarn, says: []string{"mv "},
		},
		{
			// Not an error: it just cannot encrypt a new file into the secrets
			// directory.
			name: "no rule at all",
			want: StatusWarn, says: []string{"no ", "refuses to encrypt"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := Layout{ConfigDir: dir}
			// Both rules name the keeper's recipient, so only the state varies;
			// TestDiagnoseSopsRecipients covers the rest.
			keeper := mintKey(t, dir)
			if tc.current {
				writeRule(t, layout.SopsConfigPath(), keeper)
			}
			if tc.stale {
				writeRule(t, layout.StaleSopsConfigPath(), keeper)
			}

			var report DoctorReport
			diagnoseSopsConfig(&report, DoctorOptions{ConfigDir: dir, KeeperUser: "faramir-keeper"})

			if len(report.Findings) != 1 {
				t.Fatalf("findings = %+v, want exactly one", report.Findings)
			}
			finding := report.Findings[0]
			if finding.Name != "sops config" {
				t.Errorf("check name = %q", finding.Name)
			}
			if finding.Status != tc.want {
				t.Errorf("status = %q, want %q: %s", finding.Status, tc.want, finding.Detail)
			}
			for _, want := range tc.says {
				if !strings.Contains(finding.Detail, want) {
					t.Errorf("detail does not say %q: %s", want, finding.Detail)
				}
			}
			// Warn, never failed: none of these stops the broker serving.
			if report.Failed {
				t.Errorf("a sops rule finding failed the whole report: %s", finding.Detail)
			}
		})
	}
}

// writeRule writes a creation rule listing the given recipients.  A real one: a
// rule listing none encrypts to nobody, and would test the empty case
// everywhere it is used.
func writeRule(t *testing.T, path string, recipients ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    key_groups:\n      - age:\n"
	var bodySb94 strings.Builder
	for _, recipient := range recipients {
		bodySb94.WriteString("          - " + recipient + "\n")
	}
	body += bodySb94.String()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mintKey puts an age key where diagnoseSopsConfig looks and returns the
// recipient a healthy rule has to list.
func mintKey(t *testing.T, configDir string) string {
	t.Helper()
	recipient, _, err := agekey.Generate(filepath.Join(configDir, "age.key"))
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

// A rule in the right place can still name the wrong people, which nothing else
// reports: init writes .sops.yaml once, so a keeper key restored or re-minted
// leaves it naming a recipient nobody holds, and the broker that loads nothing
// still reports healthy.
func TestDiagnoseSopsRecipients(t *testing.T) {
	for _, tc := range []struct {
		name string
		// "keeper" stands for the minted key's recipient; anything else is verbatim.
		rule    []string
		noKey   bool
		want    Status
		says    []string
		saysNot []string
	}{
		{
			name: "the keeper is a recipient", rule: []string{"keeper"},
			want: StatusOK, says: []string{"1 recipient"},
		},
		{
			name: "the keeper and a backup key",
			rule: []string{"keeper", "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
			want: StatusOK, says: []string{"2 recipient"},
		},
		{
			// Well-formed, in the right place, naming a key the keeper does not hold.
			name: "the rule has drifted off the keeper's key",
			rule: []string{"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
			want: StatusWarn, says: []string{"none of which", "cannot decrypt", "updatekeys"},
		},
		{
			name: "a rule listing nobody", rule: nil,
			want: StatusWarn, says: []string{"no age recipient", "refuses"},
		},
		{
			// Without the key there is no question to answer.
			name: "the key cannot be read", rule: []string{"keeper"}, noKey: true,
			want: StatusWarn, says: []string{"unchecked", "root"},
			saysNot: []string{"none of which"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := Layout{ConfigDir: dir}
			keeper := mintKey(t, dir)
			rule := make([]string, 0, len(tc.rule))
			for _, recipient := range tc.rule {
				if recipient == "keeper" {
					recipient = keeper
				}
				rule = append(rule, recipient)
			}
			writeRule(t, layout.SopsConfigPath(), rule...)
			if tc.noKey {
				if err := os.Remove(filepath.Join(dir, "age.key")); err != nil {
					t.Fatal(err)
				}
			}

			var report DoctorReport
			diagnoseSopsConfig(&report, DoctorOptions{ConfigDir: dir, KeeperUser: "faramir-keeper"})

			if len(report.Findings) != 1 {
				t.Fatalf("findings = %+v, want exactly one", report.Findings)
			}
			finding := report.Findings[0]
			if finding.Status != tc.want {
				t.Errorf("status = %q, want %q: %s", finding.Status, tc.want, finding.Detail)
			}
			for _, want := range tc.says {
				if !strings.Contains(finding.Detail, want) {
					t.Errorf("detail does not say %q: %s", want, finding.Detail)
				}
			}
			for _, unwanted := range tc.saysNot {
				if strings.Contains(finding.Detail, unwanted) {
					t.Errorf("detail says %q, which it cannot know: %s", unwanted, finding.Detail)
				}
			}
			// Warn at worst: the values already in the secrets directory still decrypt.
			if report.Failed {
				t.Errorf("a sops rule finding failed the whole report: %s", finding.Detail)
			}
		})
	}
}

// Both spellings sops accepts read back, the file being edited by hand: missing
// one reports a present key as absent.
func TestSopsRecipientsReadsWhatTheRuleLists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".sops.yaml")
	// The key_groups form this writes and the comma-separated shorthand.
	body := `creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - path_regex: other\.yml$
    age: age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg, age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sopsRecipients(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		"age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg",
	}
	if len(got) != len(want) {
		t.Fatalf("recipients = %q, want %q: the shorthand splits on commas and a "+
			"recipient listed twice is one recipient", got, want)
	}
	for _, recipient := range want {
		if !strings.Contains(strings.Join(got, " "), recipient) {
			t.Errorf("recipients = %q, missing %q", got, recipient)
		}
	}
}

// serves mirrors the daemon's gate, so the probes that run a brokered command
// are skipped only when it would really be refused.  A ref count is the wrong
// question: values below min_length are refused at load, so a host whose secrets
// are all too short reads its files and serves while counting zero.
func TestServesAsksWhatWasReadRatherThanHowMuchLoaded(t *testing.T) {
	for _, tc := range []struct {
		name          string
		files         []string
		errors        []string
		unresolved    []string
		count         int
		notRedactable map[string]string
		want          bool
	}{
		// The count varies across these three and the answer does not, which is
		// what says it is not being consulted.
		{name: "read one file holding values",
			files: []string{"a.sops.yml"}, count: 3, want: true},
		{name: "read one file holding nothing",
			files: []string{"a.sops.yml"}, count: 0, want: true},
		{name: "read one file, every value too short to redact",
			files: []string{"a.sops.yml"}, count: 0,
			notRedactable: map[string]string{"pin": "shorter than 8 characters"}, want: true},
		{name: "one entry named nothing, another loaded",
			files: []string{"a.sops.yml"}, count: 3,
			unresolved: []string{"/b/*.sops.yml"}, want: true},
		{name: "nothing matched", unresolved: []string{"/b/*.sops.yml"}, want: false},
		{name: "nothing configured", want: false},
		{name: "a file that did not load",
			files: []string{"a.sops.yml"}, count: 3,
			errors: []string{"a.sops.yml: bad mac"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report checkReport
			report.Secrets.Files = tc.files
			report.Secrets.Errors = tc.errors
			report.Secrets.UnresolvedPatterns = tc.unresolved
			report.Secrets.Count = tc.count
			report.Secrets.NotRedactable = tc.notRedactable
			if got := report.serves(); got != tc.want {
				t.Errorf("serves() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --check exits non-zero for several states at once, so the exit code cannot
// say which.  Refs the redactor refused are the one state that is not about the
// install: the store loaded, the daemons serve, and a value is too short to
// cover.  Telling it apart is what lets init finish and doctor name it.
func TestOnlyNotRedactableSeparatesAValueFromAFault(t *testing.T) {
	loaded := func() checkReport {
		var r checkReport
		r.Secrets.Count = 3
		r.Secrets.Files = []string{"app.sops.yml"}
		r.Secrets.NotRedactable = map[string]string{"short/pin": "shorter than 8 characters"}
		return r
	}
	for _, tc := range []struct {
		name   string
		report func() checkReport
		want   bool
	}{
		{"a short ref and nothing else", loaded, true},
		{"no short refs at all", func() checkReport {
			r := loaded()
			r.Secrets.NotRedactable = nil
			return r
		}, false},
		{"a socket policy problem beside it", func() checkReport {
			r := loaded()
			r.Policy = []string{"[keeper] allowed_user names the wrong account"}
			return r
		}, false},
		{"a file that did not load beside it", func() checkReport {
			r := loaded()
			r.Secrets.Errors = []string{"app.sops.yml: bad mac"}
			return r
		}, false},
		{"an entry that named no file beside it", func() checkReport {
			r := loaded()
			r.Secrets.UnresolvedPatterns = []string{"/etc/faramir/secrets/*.sops.yml"}
			return r
		}, false},
		{"nothing loaded at all", func() checkReport {
			r := loaded()
			r.Secrets.Count = 0
			return r
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.report().onlyNotRedactable(); got != tc.want {
				t.Errorf("onlyNotRedactable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The refs are named in both messages, so the operator is told which value to
// lengthen rather than that something is wrong.
func TestRefusedRefsNamesEveryRefAndItsReason(t *testing.T) {
	var r checkReport
	r.Secrets.NotRedactable = map[string]string{
		"short/pin": "shorter than 8 characters",
		"api/kid":   "shorter than 8 characters",
	}
	got := r.refusedRefs()
	for _, want := range []string{"short/pin", "api/kid", "shorter than 8 characters"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusedRefs() = %q, missing %q", got, want)
		}
	}
	// Sorted: a map's order would make the message differ between two runs on
	// one unchanged host.
	if !strings.HasPrefix(got, "api/kid") {
		t.Errorf("refusedRefs() = %q, want the refs in a stable order", got)
	}
}

// diagnoseUnits reports the states the caller sampled before it opened the
// broker socket.  Reading them itself would read them after that round trip,
// which starts the sockets the broker Requires=: the fault repairs itself
// between doctor arriving and doctor looking.
func TestUnitsReportTheStateSampledBeforeTheBrokerWasAsked(t *testing.T) {
	original := systemdRunning
	systemdRunning = func() bool { return true }
	defer func() { systemdRunning = original }()

	var report DoctorReport
	diagnoseUnits(&report, DoctorOptions{SocketStates: map[string]string{
		"faramir-keeper.socket": "inactive",
		"faramir-exec.socket":   "active",
		"faramir-broker.socket": "active",
	}})
	var failed, ok int
	for _, finding := range report.Findings {
		switch finding.Status {
		case StatusFailed:
			failed++
			if !strings.Contains(finding.Detail, "faramir-keeper.socket is inactive") {
				t.Errorf("the failure does not name the socket and its state: %q", finding.Detail)
			}
		case StatusOK:
			ok++
		case StatusNA, StatusWarn:
			// Neither is what this fixture produces; counted nowhere on purpose.
		}
	}
	if failed != 1 || ok != 2 {
		t.Errorf("got %d failed and %d ok, want 1 and 2", failed, ok)
	}
}

// An upgrade that installed the binary without restarting the daemons leaves
// every other finding describing the build that is not running.
func TestVersionSkewIsAFindingOfItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running string
		want    Status
	}{
		{name: "the broker runs what is installed", running: version.Version, want: StatusOK},
		{name: "the daemons were never restarted", running: "0.0.1", want: StatusFailed},
		{name: "no broker answered", running: "", want: StatusWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report DoctorReport
			diagnoseVersion(&report, DoctorOptions{BrokerVersion: tc.running})
			if len(report.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(report.Findings))
			}
			if got := report.Findings[0].Status; got != tc.want {
				t.Errorf("status = %q, want %q (detail: %s)",
					got, tc.want, report.Findings[0].Detail)
			}
			// Only a fail is an exit code, so a broker that did not answer must not
			// become one: doctor is run against a stopped install on purpose.
			if wantFailed := tc.want == StatusFailed; report.Failed != wantFailed {
				t.Errorf("report.Failed = %v, want %v", report.Failed, wantFailed)
			}
		})
	}
}

// The broker declining to run the probe is a statement about the value set, not
// about the agent.  Reported as the agent's own answer it becomes a failure
// against a host whose agent is fine, and the plain answers must keep working
// when an error is present, ssh-add exiting non-zero on an empty agent.
func TestTheSSHProbeTellsARefusalFromAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want sshProbeResult
	}{
		{
			name: "the agent answered",
			out:  "256 SHA256:abc faramir broker on host (ED25519)\n",
			want: sshProbeHasKey,
		},
		{
			name: "the agent answered despite a non-zero exit",
			out:  "256 SHA256:abc faramir broker on host (ED25519)\n",
			err:  errors.New("exit status 1"),
			want: sshProbeHasKey,
		},
		{
			name: "the broker refused the probe",
			err:  errors.New("faramir: " + refusedCode + ": the broker does not hold every managed value"),
			want: sshProbeRefused,
		},
		{
			name: "the agent holds nothing",
			out:  "The agent has no identities.\n",
			err:  errors.New("exit status 1"),
			want: sshProbeEmpty,
		},
		{
			name: "nothing answered",
			err:  errors.New("exit status 2"),
			want: sshProbeUnreachable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySSHProbe(tc.out, tc.err); got != tc.want {
				t.Errorf("classifySSHProbe = %v, want %v", got, tc.want)
			}
		})
	}
}

// A broker probe that never ran says nothing about the value set, so the ssh
// agent check has to run rather than report a broker holding values as one
// holding none.  A broker that answered nothing is the opposite: the probe
// sends a brokered command, so there is no answer to be had, and reporting it
// as an agent that could not be reached fails a stopped install over a check
// about something else.
func TestWhatSkipsTheSSHAgentProbe(t *testing.T) {
	const running = "1.2.3"
	for _, tc := range []struct {
		name    string
		serves  brokerServes
		version string
		want    string
	}{
		{
			name:    "a broker known to serve nothing",
			serves:  servesNothing,
			version: running,
			want:    sshAgentRefused,
		},
		{
			name:   "a broker that answered nothing",
			serves: servesUnknown,
			want:   sshAgentUnanswered,
		},
		{
			name:    "a broker probe that never ran",
			serves:  servesUnknown,
			version: running,
			want:    "",
		},
		{
			name:    "a broker known to serve values",
			serves:  servesValues,
			version: running,
			want:    "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipSSHProbe(tc.serves, tc.version); got != tc.want {
				t.Errorf("skipSSHProbe = %q, want %q", got, tc.want)
			}
		})
	}

	// No key configured is the host that arranges SSH some other way, and is an
	// answer rather than a check that went unmade.
	var noKey DoctorReport
	diagnoseSSHAgent(&noKey, DoctorOptions{}, &config.Config{}, servesUnknown)
	if len(noKey.Findings) != 1 || noKey.Findings[0].Status != StatusOK {
		t.Fatalf("no [ssh] key: got %+v", noKey.Findings)
	}
	if noKey.NotAsked != 0 {
		t.Errorf("NotAsked = %d, want 0 for a check that was answered", noKey.NotAsked)
	}
}

// The brokered command check runs a command rather than reading a mode, so
// every state where the command cannot be sent has to be a skip.  Run anyway it
// reports a broker that is refusing or not running as a boundary that does not
// hold.
func TestTheBrokeredCommandIsSkippedWhenItCannotBeSent(t *testing.T) {
	const running = "1.2.3"
	for _, tc := range []struct {
		name    string
		serves  brokerServes
		version string
	}{
		{name: "a broker known to serve nothing", serves: servesNothing, version: running},
		{name: "a --check that did not report", serves: servesUnknown, version: running},
		{name: "a broker that answered nothing", serves: servesValues},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report DoctorReport
			diagnoseBrokered(&report, DoctorOptions{BrokerVersion: tc.version}, tc.serves)
			if len(report.Findings) != 1 || report.Findings[0].Status != StatusWarn {
				t.Fatalf("got %+v", report.Findings)
			}
			if report.NotAsked != 1 {
				t.Errorf("NotAsked = %d, want the skipped check counted", report.NotAsked)
			}
			if report.Failed {
				t.Error("report.Failed = true, want a skip rather than an exit code")
			}
		})
	}
}

// A refusal is the answer against a broker holding nothing and a contradiction
// against one --check found holding values.  Reported as a skip in the second
// case it repeats a claim --check disproved and names no fault to fix.
func TestARefusalFromABrokerHoldingValuesIsAFailure(t *testing.T) {
	cfg := &config.Config{}
	cfg.Ssh.Key = "/etc/faramir/id_ed25519"
	refusal := errors.New("faramir: " + refusedCode + ": the broker does not hold every managed value")

	var contradicted DoctorReport
	reportSSHProbe(&contradicted, cfg, servesValues, "", refusal)
	if len(contradicted.Findings) != 1 || contradicted.Findings[0].Status != StatusFailed {
		t.Fatalf("--check read every file and the daemon refuses: got %+v", contradicted.Findings)
	}
	if contradicted.NotAsked != 0 {
		t.Errorf("NotAsked = %d, want 0: the probe was put and answered", contradicted.NotAsked)
	}

	// Without root --check does not report, so a refusal is the only word on the
	// value set and stands as the reason the probe went unanswered.
	var unestablished DoctorReport
	reportSSHProbe(&unestablished, cfg, servesUnknown, "", refusal)
	if len(unestablished.Findings) != 1 || unestablished.Findings[0].Detail != sshAgentRefused {
		t.Fatalf("no --check report to contradict: got %+v", unestablished.Findings)
	}
	if unestablished.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want the unanswered check counted", unestablished.NotAsked)
	}
}

// stubLogrotate points the check at files a test wrote and puts a program named
// logrotate on $PATH.  The real rule, the real state file and the real log
// belong to the host running the tests, and every state worth checking here is
// one that host is not in.  An empty body leaves that file out.
func stubLogrotate(t *testing.T, rule, state string) (rulePath, statePath string) {
	t.Helper()
	dir := t.TempDir()
	rulePath = filepath.Join(dir, "faramir")
	statePath = filepath.Join(dir, "status")
	for path, body := range map[string]string{rulePath: rule, statePath: state} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	originalRule, originalState := logrotateConfig, logrotateStatePaths
	logrotateConfig, logrotateStatePaths = rulePath, []string{statePath}
	t.Cleanup(func() { logrotateConfig, logrotateStatePaths = originalRule, originalState })

	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "logrotate"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return rulePath, statePath
}

// Every state below leaves the install looking healthy from its own side: the
// rule is where init put it, logrotate is installed, and the log grows anyway.
// What tells them apart is on disk, so that is what the check reads.
func TestDiagnoseLogRotationAsksWhatIsOnDisk(t *testing.T) {
	const applied = "logrotate state -- version 2\n\"LOG\" 2026-8-11-0:0:0\n"
	for _, tc := range []struct {
		name  string
		rule  string
		state string
		size  int64
		want  Status
		says  []string
	}{
		{
			name: "the rule init writes, and logrotate has applied it",
			rule: "LOG {\n    weekly\n    rotate 8\n}\n", state: applied,
			want: StatusOK, says: []string{"LOG"},
		},
		{
			name: "a glob that covers it",
			rule: "DIR/*.log {\n    weekly\n}\n", state: applied,
			want: StatusOK,
		},
		{
			name:  "no rule at all",
			state: applied,
			want:  StatusFailed, says: []string{"does not exist", "faramir init"},
		},
		{
			// [audit] log_path moved after the install, which leaves the rule
			// bounding a path nothing writes.
			name: "a rule for a log the broker no longer writes",
			rule: "DIR/moved.log {\n    weekly\n}\n", state: applied,
			want: StatusFailed, says: []string{"moved.log", "LOG", "log_path"},
		},
		{
			name:  "a rule logrotate reads past every run",
			rule:  "LOG {\n    weekly\n}\n",
			state: "logrotate state -- version 2\n\"/var/log/syslog\" 2026-8-11-0:0:0\n",
			want:  StatusWarn, says: []string{"has not applied", "timer or cron"},
		},
		{
			name: "a host logrotate has never run on",
			rule: "LOG {\n    weekly\n}\n",
			want: StatusWarn, says: []string{"has not run", "timer or cron"},
		},
		{
			name: "a log far past what the rule rotates at",
			rule: "LOG {\n    weekly\n}\n", state: applied, size: 65 << 20,
			want: StatusWarn, says: []string{"past", "timer or cron"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.log")
			render := strings.NewReplacer("LOG", logPath, "DIR", dir)
			stubLogrotate(t, render.Replace(tc.rule), render.Replace(tc.state))
			if err := os.WriteFile(logPath, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.size > 0 {
				// Sparse: what is read is the size, and 65MB of it costs nothing.
				if err := os.Truncate(logPath, tc.size); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.Config{}
			cfg.Audit.LogPath = logPath

			var report DoctorReport
			diagnoseLogRotation(&report, cfg)

			if len(report.Findings) != 1 {
				t.Fatalf("findings = %+v, want exactly one", report.Findings)
			}
			finding := report.Findings[0]
			if finding.Status != tc.want {
				t.Errorf("status = %q, want %q: %s", finding.Status, tc.want, finding.Detail)
			}
			if report.Failed != (tc.want == StatusFailed) {
				t.Errorf("Failed = %v for a %q finding: %s", report.Failed, tc.want, finding.Detail)
			}
			for _, want := range tc.says {
				if !strings.Contains(finding.Detail, render.Replace(want)) {
					t.Errorf("detail does not say %q: %s", want, finding.Detail)
				}
			}
			// The log is named whatever the verdict: a reader has to know which
			// file the finding is about.
			if !strings.Contains(finding.Detail, logPath) {
				t.Errorf("detail does not name %s: %s", logPath, finding.Detail)
			}
		})
	}
}

// The state file is root's and the log is the broker's, so the last two
// questions cannot be put by every caller.  Told as an answer they are the pass
// a stat that failed would otherwise be read as.
func TestLogRotationSaysWhichQuestionsNeededRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this asserts what a caller who cannot read the state file is told")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	_, statePath := stubLogrotate(t, logPath+" {\n    weekly\n}\n",
		"logrotate state -- version 2\n\""+logPath+"\" 2026-8-11-0:0:0\n")
	if err := os.Chmod(statePath, 0o000); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Audit.LogPath = logPath

	var report DoctorReport
	diagnoseLogRotation(&report, cfg)

	if len(report.Findings) != 1 || report.Findings[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warn", report.Findings)
	}
	if report.Failed {
		t.Errorf("a question nobody could put failed the report: %s", report.Findings[0].Detail)
	}
	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want the unput question counted", report.NotAsked)
	}
	// What was established still gets said, that being the half a caller
	// without root can act on.
	if !strings.Contains(report.Findings[0].Detail, logPath) {
		t.Errorf("detail does not name the log: %s", report.Findings[0].Detail)
	}
}

// The file list is what the check compares against config.toml, so a directive
// read as a path reports a rule covering files nothing writes, and a path
// missed reports a covered log as unbounded.
func TestLogrotateLogsReadsTheFileListAndNotTheDirectives(t *testing.T) {
	// `su user group` and `create mode user group` name the same account twice
	// here because the broker's group has its name; that is logrotate's syntax,
	// not a repeated word.
	//nolint:dupword // logrotate's su and create directives take a user and a group
	rule := `# The audit log, and a second file to show two on one block.
"/var/log/faramir/audit.log" /var/log/faramir/other.log {
    su faramir-broker faramir-broker
    create 0600 faramir-broker faramir-broker
    weekly
    rotate 8
    maxsize 16M
}
/var/log/faramir/attached.log{
    weekly
}
`
	path := filepath.Join(t.TempDir(), "faramir")
	if err := os.WriteFile(path, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	logs, err := logrotateLogs(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/var/log/faramir/audit.log",
		"/var/log/faramir/other.log",
		"/var/log/faramir/attached.log",
	}
	if strings.Join(logs, " ") != strings.Join(want, " ") {
		t.Errorf("logs = %q, want %q", logs, want)
	}
}

// A rule that does not name the log covers it anyway when it names a glob that
// matches, so the comparison cannot be a string one.
func TestLogrotateCoversMatchesAGlob(t *testing.T) {
	for _, tc := range []struct {
		named string
		want  bool
	}{
		{"/var/log/faramir/audit.log", true},
		{"/var/log/faramir/*.log", true},
		{"/var/log/faramir/*", true},
		{"/var/log/faramir/other.log", false},
		{"/var/log/*/audit.log", true},
		{"/var/log/[", false}, // a pattern filepath.Match rejects is not a match
	} {
		if got := logrotateCovers([]string{tc.named}, "/var/log/faramir/audit.log"); got != tc.want {
			t.Errorf("a rule naming %s covers the audit log = %v, want %v", tc.named, got, tc.want)
		}
	}
}

// The state file is how the check knows the rule is applied rather than merely
// installed, so every line of it that names a log has to be read.
func TestLogrotateStateLogsNamesEveryLogItHasProcessed(t *testing.T) {
	state := `logrotate state -- version 2
"/var/log/faramir/audit.log" 2026-8-11-0:0:0
"/var/log/a name with spaces.log" 2026-8-4-0:0:0
/var/log/unquoted.log 2026-8-4-0:0:0
`
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}
	logs, err := logrotateStateLogs(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/var/log/faramir/audit.log",
		"/var/log/a name with spaces.log",
		"/var/log/unquoted.log",
	}
	if strings.Join(logs, "|") != strings.Join(want, "|") {
		t.Errorf("logs = %q, want %q", logs, want)
	}
}
