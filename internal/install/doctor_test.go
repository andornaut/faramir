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
	for _, recipient := range recipients {
		body += "          - " + recipient + "\n"
	}
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
		name       string
		files      []string
		errors     []string
		unresolved []string
		count      int
		want       bool
	}{
		{name: "read one file holding nothing", files: []string{"a.sops.yml"}, want: true},
		{name: "read one file, every value too short",
			files: []string{"a.sops.yml"}, count: 0, want: true},
		{name: "one entry named nothing, another loaded",
			files: []string{"a.sops.yml"}, unresolved: []string{"/b/*.sops.yml"}, want: true},
		{name: "nothing matched", unresolved: []string{"/b/*.sops.yml"}, want: false},
		{name: "nothing configured", want: false},
		{name: "a file that did not load",
			files: []string{"a.sops.yml"}, errors: []string{"a.sops.yml: bad mac"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report checkReport
			report.Secrets.Files = tc.files
			report.Secrets.Errors = tc.errors
			report.Secrets.UnresolvedPatterns = tc.unresolved
			report.Secrets.Count = tc.count
			if got := report.serves(); got != tc.want {
				t.Errorf("serves() = %v, want %v", got, tc.want)
			}
		})
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
