package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sealed writes a file shaped like one sops encrypted: the recipient field is
// cleartext metadata, which is all this check reads. A real encryption would
// need a key and a sops on PATH to assert something the regex already decides.
func sealed(t *testing.T, dir, name string, recipients ...string) string {
	t.Helper()
	var body strings.Builder
	body.WriteString("k: ENC[AES256_GCM,data:xx,type:str]\nsops:\n    age:\n")
	for _, recipient := range recipients {
		body.WriteString("        - recipient: " + recipient + "\n")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func driftReport(t *testing.T, dir string, patterns ...string) DoctorReport {
	t.Helper()
	layout := Layout{ConfigDir: dir}
	var report DoctorReport
	diagnoseRecipientDrift(&report, DoctorOptions{
		ConfigDir: dir, KeeperUser: "faramir-keeper", SecretsPatterns: patterns,
	}, layout.SopsConfigPath())
	return report
}

func TestRecipientDriftPassesWhenTheStoreAgrees(t *testing.T) {
	dir := t.TempDir()
	keeper := mintKey(t, dir)
	writeRule(t, Layout{ConfigDir: dir}.SopsConfigPath(), keeper)
	store := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	sealed(t, store, "a.sops.yml", keeper)
	sealed(t, store, "b.sops.yml", keeper)

	finding := onlyFinding(t, driftReport(t, dir, filepath.Join(store, "*.sops.yml")),
		"recipient drift")
	if finding.Status != StatusOK {
		t.Errorf("status = %q, want ok: %s", finding.Status, finding.Detail)
	}
}

// The state the recipient commands exist to prevent, and the one nothing else
// reports: the rule names a reader the ciphertext is not sealed to. A reseal
// that failed partway leaves exactly this.
func TestRecipientDriftFailsWhenTheCiphertextLagsTheRule(t *testing.T) {
	dir := t.TempDir()
	keeper := mintKey(t, dir)
	const backup = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsjqsjqs"
	writeRule(t, Layout{ConfigDir: dir}.SopsConfigPath(), keeper, backup)
	store := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	// Written before the rule grew a second recipient, which is what a
	// half-finished pass leaves behind.
	sealed(t, store, "stale.sops.yml", keeper)

	finding := onlyFinding(t, driftReport(t, dir, filepath.Join(store, "*.sops.yml")),
		"recipient drift")
	if finding.Status != StatusFailed {
		t.Fatalf("status = %q, want failed: %s", finding.Status, finding.Detail)
	}
	for _, want := range []string{"stale.sops.yml", backup, "reader reseal"} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("detail does not name %q: %s", want, finding.Detail)
		}
	}
}

// A file sealed to nothing is not sealed to the wrong set. What it is instead
// belongs to `rule coverage` and to the broker's own --check, and reporting it
// here would be two checks failing for one cause.
func TestRecipientDriftIgnoresAFileSealedToNothing(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, Layout{ConfigDir: dir}.SopsConfigPath(), mintKey(t, dir))
	store := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "plain.sops.yml"), []byte("k: v\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report := driftReport(t, dir, filepath.Join(store, "*.sops.yml"))
	if len(report.Findings) != 0 {
		t.Errorf("reported %+v; a file sealed to nothing is another check's", report.Findings)
	}
	if report.NotAsked != 0 {
		t.Errorf("NotAsked = %d: reading the file succeeded, so nothing went unasked",
			report.NotAsked)
	}
}

// Without the patterns there is nothing to compare the rule against, and a
// silence here would read as a store confirmed rather than one not examined.
func TestRecipientDriftWithoutThePatternsIsUnasked(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, Layout{ConfigDir: dir}.SopsConfigPath(), mintKey(t, dir))

	report := driftReport(t, dir)
	finding := onlyFinding(t, report, "recipient drift")
	if finding.Status != StatusWarn {
		t.Errorf("status = %q, want warn: %s", finding.Status, finding.Detail)
	}
	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1", report.NotAsked)
	}
}
