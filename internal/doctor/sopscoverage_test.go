package doctor

// What .sops.yaml says, checked against what sops will accept and against the
// files it has to reach.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/sopstest"
)

// .sops.yaml is 0644 and the documented way to add a recipient is to edit it by
// hand, so nothing between the operator and the file looks at what was typed.
// An identity written where a recipient belongs is the key that opens the
// secrets directory, readable by every account on the host.
func TestARecipientSopsWillNotTakeIsReported(t *testing.T) {
	for _, tc := range []struct {
		name, entry, says string
	}{
		{
			name:  "an identity, the private half",
			entry: "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
			says:  "world-readable",
		},
		{
			name:  "not a recipient of any kind",
			entry: "not-a-key",
			says:  "unknown recipient type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := hostlayout.Layout{ConfigDir: dir}
			mintKey(t, dir)
			sopstest.WriteRule(t, layout.SopsConfigPath(), tc.entry)

			var report Report
			diagnoseSopsConfig(&report, Options{ConfigDir: dir, KeeperUser: "faramir-keeper"})

			finding := onlyFinding(t, report, "sops config")
			if finding.Status != StatusFailed {
				t.Errorf("status = %q, want failed: %s", finding.Status, finding.Detail)
			}
			if !strings.Contains(finding.Detail, tc.says) {
				t.Errorf("detail does not say %q: %s", tc.says, finding.Detail)
			}
		})
	}
}

// doctor and reseal read the same file, so they have to read it the same way.
// A rule whose key groups leave the keeper out, with the keeper named only in
// the bare `age:` beside them, is one sops seals every new file without: the
// check exists to catch exactly that, and reporting the shorthand would report
// it as healthy.
func TestTheKeeperInTheIgnoredShorthandIsNotAReader(t *testing.T) {
	dir := t.TempDir()
	layout := hostlayout.Layout{ConfigDir: dir}
	keeper := mintKey(t, dir)
	other := "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	rule := "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n" +
		"    age: " + keeper + "\n" +
		"    key_groups:\n      - age:\n          - " + other + "\n"
	if err := os.WriteFile(layout.SopsConfigPath(), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}

	var report Report
	diagnoseSopsConfig(&report, Options{ConfigDir: dir, KeeperUser: "faramir-keeper"})

	finding := onlyFinding(t, report, "sops config")
	if finding.Status != StatusWarn {
		t.Errorf("status = %q, want warn: sops seals to the key groups alone, so "+
			"the keeper is not a reader here: %s", finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, "none of which") {
		t.Errorf("detail does not say the keeper is missing: %s", finding.Detail)
	}
}

// A shorthand written as a list is valid for sops and read by reseal, so doctor
// reporting the file as unparseable would fail a host that works.
func TestAListShorthandIsReadRatherThanRefused(t *testing.T) {
	dir := t.TempDir()
	layout := hostlayout.Layout{ConfigDir: dir}
	keeper := mintKey(t, dir)
	rule := "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n" +
		"    age:\n      - " + keeper + "\n"
	if err := os.WriteFile(layout.SopsConfigPath(), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}

	var report Report
	diagnoseSopsConfig(&report, Options{ConfigDir: dir, KeeperUser: "faramir-keeper"})

	finding := onlyFinding(t, report, "sops config")
	if finding.Status != StatusOK {
		t.Errorf("status = %q, want ok: %s", finding.Status, finding.Detail)
	}
}

// requireSops fails where the real binary is absent: which files a creation
// rule governs is sops' own question, and this check exists because answering
// it anywhere else would be a second opinion free to disagree with it.
func requireSops(t *testing.T) {
	t.Helper()
	sopstest.SopsBinary(t)
}

// A rule that reaches none of the managed files is a store `faramir vault edit` and
// `faramir reader reseal` cannot write back, and nothing else on the host says so: the
// values still decrypt, the broker still serves them, and the failure waits
// until somebody edits one.
func TestRuleCoverageIsCheckedAgainstTheManagedFiles(t *testing.T) {
	requireSops(t)
	for _, tc := range []struct {
		name      string
		pathRegex string
		want      Status
		says      string
	}{
		{
			name:      "the rule the installer writes",
			pathRegex: `\.sops\.ya?ml$`,
			want:      StatusOK, says: "covers all",
		},
		{
			name:      "narrowed to somewhere the store is not",
			pathRegex: `^elsewhere/.*\.sops\.yml$`,
			want:      StatusFailed, says: "no creation rule matching",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := hostlayout.Layout{ConfigDir: dir}
			keeper := mintKey(t, dir)
			rule := "creation_rules:\n  - path_regex: " + tc.pathRegex +
				"\n    key_groups:\n      - age:\n          - " + keeper + "\n"
			if err := os.WriteFile(layout.SopsConfigPath(), []byte(rule), 0o644); err != nil {
				t.Fatal(err)
			}
			secrets := filepath.Join(dir, "secrets")
			if err := os.MkdirAll(secrets, 0o700); err != nil {
				t.Fatal(err)
			}
			store := filepath.Join(secrets, "store.sops.yml")
			if err := os.WriteFile(store, []byte("k: v\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			var report Report
			diagnoseSopsConfig(&report, Options{
				ConfigDir: dir, KeeperUser: "faramir-keeper",
				SecretsPatterns: []string{filepath.Join(secrets, "*.sops.yml")},
			})

			finding := onlyFinding(t, report, "rule coverage")
			if finding.Status != tc.want {
				t.Errorf("status = %q, want %q: %s", finding.Status, tc.want, finding.Detail)
			}
			if !strings.Contains(finding.Detail, tc.says) {
				t.Errorf("detail does not say %q: %s", tc.says, finding.Detail)
			}
		})
	}
}

// Without the patterns there is nothing to check the rule against, and a rule
// reaching none of the files looks exactly like a rule reaching all of nothing.
// Reported as unasked, and counted, rather than as a pass.
func TestRuleCoverageWithoutThePatternsIsUnasked(t *testing.T) {
	dir := t.TempDir()
	layout := hostlayout.Layout{ConfigDir: dir}
	sopstest.WriteRule(t, layout.SopsConfigPath(), mintKey(t, dir))

	var report Report
	diagnoseSopsRuleCoverage(&report, Options{ConfigDir: dir,
		KeeperUser: "faramir-keeper"}, layout.SopsConfigPath())

	finding := onlyFinding(t, report, "rule coverage")
	if finding.Status != StatusWarn {
		t.Errorf("status = %q, want warn: %s", finding.Status, finding.Detail)
	}
	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1: a warn that stands for a question nobody "+
			"put has to be counted, or the totals read as a full examination",
			report.NotAsked)
	}
}

// The secrets directory is 2750 and the group is the keeper's, and
// filepath.Glob reports a directory it cannot list as no matches and no error.
// So "there are no managed files" and "this account may not see them" arrive
// here identically, and doctor run without sudo would otherwise report a host
// full of managed files as having nothing to cover.
func TestRuleCoverageCannotSeeIntoTheStoreIsUnasked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory whatever its mode, so there is no closed door to meet")
	}
	dir := t.TempDir()
	layout := hostlayout.Layout{ConfigDir: dir}
	sopstest.WriteRule(t, layout.SopsConfigPath(), mintKey(t, dir))
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "store.sops.yml"), []byte("k: v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Closed after the file is in it, so what is being reported is a store with
	// contents rather than one that is empty.
	if err := os.Chmod(secrets, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secrets, 0o700) })

	var report Report
	diagnoseSopsConfig(&report, Options{
		ConfigDir: dir, KeeperUser: "faramir-keeper",
		SecretsPatterns: []string{filepath.Join(secrets, "*.sops.yml")},
	})

	finding := onlyFinding(t, report, "rule coverage")
	if finding.Status != StatusWarn {
		t.Errorf("status = %q, want warn: %s", finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, "cannot be listed") {
		t.Errorf("detail does not say the store could not be read: %s", finding.Detail)
	}
	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1", report.NotAsked)
	}
}

// A caller who can read one pattern's directory and not another's would
// otherwise get a confident answer about half a store: what resolved is checked
// and reported as covering everything, while the files behind the closed door
// are the ones nobody looked at.
func TestRuleCoverageNamesAClosedDoorEvenWhenSomethingResolved(t *testing.T) {
	requireSops(t)
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory whatever its mode, so there is no closed door to meet")
	}
	dir := t.TempDir()
	layout := hostlayout.Layout{ConfigDir: dir}
	sopstest.WriteRule(t, layout.SopsConfigPath(), mintKey(t, dir))

	open := filepath.Join(dir, "open")
	shut := filepath.Join(dir, "shut")
	for _, path := range []string{open, shut} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "store.sops.yml"), []byte("k: v\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(shut, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shut, 0o700) })

	var report Report
	diagnoseSopsRuleCoverage(&report, Options{
		ConfigDir: dir, KeeperUser: "faramir-keeper",
		SecretsPatterns: []string{
			filepath.Join(open, "*.sops.yml"),
			filepath.Join(shut, "*.sops.yml"),
		},
	}, layout.SopsConfigPath())

	finding := onlyFinding(t, report, "rule coverage")
	if finding.Status != StatusWarn {
		t.Errorf("status = %q, want warn: %s", finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, "cannot be listed") {
		t.Errorf("detail does not name the closed directory: %s", finding.Detail)
	}
	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1", report.NotAsked)
	}
}

// A host with the patterns but no file matching them yet has nothing for the
// rule to cover, which is not a pass and not a failure.
func TestRuleCoverageWithNoManagedFileIsNotApplicable(t *testing.T) {
	dir := t.TempDir()
	layout := hostlayout.Layout{ConfigDir: dir}
	sopstest.WriteRule(t, layout.SopsConfigPath(), mintKey(t, dir))

	var report Report
	diagnoseSopsConfig(&report, Options{
		ConfigDir: dir, KeeperUser: "faramir-keeper",
		SecretsPatterns: []string{filepath.Join(dir, "secrets", "*.sops.yml")},
	})

	finding := onlyFinding(t, report, "rule coverage")
	if finding.Status != StatusNA {
		t.Errorf("status = %q, want n/a: %s", finding.Status, finding.Detail)
	}
}
