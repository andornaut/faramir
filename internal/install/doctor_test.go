package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agekey"
)

// sops takes the first .sops.yaml walking up from the working directory, so a
// copy in the store shadows the one above it.  Each of the four states reads
// differently, the remedies being different: compare recipients and delete one,
// or move it.  No systemd, accounts or root needed.
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
			name: "a copy in the store shadows it", current: true, stale: true,
			want: StatusWarn, says: []string{"shadows", "recipients", "rm "},
		},
		{
			name: "only the copy earlier installs left behind", stale: true,
			want: StatusWarn, says: []string{"mv "},
		},
		{
			// Not an error: it just cannot encrypt a new file into the store.
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
		// "keeper" stands for the minted key's recipient; anything else is
		// verbatim.
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
			// Well-formed, in the right place, naming a key the keeper does not
			// hold.
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
			// Warn at worst: the values already in the store still decrypt.
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
