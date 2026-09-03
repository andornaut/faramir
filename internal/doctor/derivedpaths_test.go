package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// derivedFixture is a file, a symlink to it, and a second file the symlink can
// be repointed at, all resolved so that the paths compare as strings.
func derivedFixture(t *testing.T) (link, target, other string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target = filepath.Join(dir, "credentials.json")
	other = filepath.Join(dir, "credentials.new.json")
	for _, path := range []string{target, other} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link = filepath.Join(dir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link, target, other
}

func repoint(t *testing.T, link, to string) {
	t.Helper()
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(to, link); err != nil {
		t.Fatal(err)
	}
}

func derivedReport(entries ...config.BlockedPath) Report {
	return derivedReportWithLinks(nil, entries...)
}

func derivedReportWithLinks(links []config.Link, entries ...config.BlockedPath) Report {
	var report Report
	cfg := &config.Config{}
	cfg.Secret.Blocked = entries
	cfg.Secret.Links = links
	diagnoseDerivedPaths(&report, cfg)
	return report
}

func TestADerivedEntryStillNamingTheTargetIsOK(t *testing.T) {
	link, target, _ := derivedFixture(t)

	// Both directions: a block entry's derivation and a link's.
	for _, entry := range []config.BlockedPath{
		{Path: target, DerivedFrom: link},
		{Path: link, DerivedFrom: target},
	} {
		finding := findingFor(t, derivedReport(entry), "derived paths")
		if finding.Status != StatusOK {
			t.Errorf("%+v: status = %s (%s), want ok", entry, finding.Status, finding.Detail)
		}
	}
}

func TestARepointedSymlinkFailsAndNamesTheFix(t *testing.T) {
	link, target, other := derivedFixture(t)
	repoint(t, link, other)

	finding := findingFor(t, derivedReport(config.BlockedPath{Path: target, DerivedFrom: link}),
		"derived paths")

	if finding.Status != StatusFailed {
		t.Fatalf("status = %s (%s), want failed", finding.Status, finding.Detail)
	}
	for _, want := range []string{link + " now resolves to " + other, "block add --path " + link} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("detail = %q, want %q in it", finding.Detail, want)
		}
	}
}

// A link's spelling that resolves elsewhere now is the same drift from the
// other side, with a different fix: declaring the link's file again would not
// replace the spelling, the link keeping it, so the entry is named directly.
func TestARepointedSpellingFailsAndNamesTheFix(t *testing.T) {
	link, target, other := derivedFixture(t)
	repoint(t, link, other)

	finding := findingFor(t, derivedReportWithLinks(
		[]config.Link{{Ref: "gh/token", Path: target}},
		config.BlockedPath{Path: link, DerivedFrom: target}), "derived paths")

	if finding.Status != StatusFailed {
		t.Fatalf("status = %s (%s), want failed", finding.Status, finding.Detail)
	}
	for _, want := range []string{link + " now resolves to " + other, "block rm --path " + link} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("detail = %q, want %q in it", finding.Detail, want)
		}
	}
}

func TestAFormerSymlinkFails(t *testing.T) {
	link, target, _ := derivedFixture(t)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	finding := findingFor(t, derivedReport(config.BlockedPath{Path: target, DerivedFrom: link}),
		"derived paths")

	if finding.Status != StatusFailed || !strings.Contains(finding.Detail, "is a symlink any more") {
		t.Errorf("status = %s, detail = %q, want failed for a symlink that is a file now", finding.Status, finding.Detail)
	}
}

// A path that is not there is not judged: the entry may be waiting for a
// volume, and what the symlink would resolve to cannot be read.
func TestAnAbsentPathIsNotJudged(t *testing.T) {
	link, target, _ := derivedFixture(t)
	absent := filepath.Join(filepath.Dir(target), "absent.json")

	for _, entry := range []config.BlockedPath{
		{Path: absent, DerivedFrom: link},
		{Path: target, DerivedFrom: absent},
	} {
		finding := findingFor(t, derivedReport(entry), "derived paths")
		if finding.Status != StatusOK || !strings.Contains(finding.Detail, "no derived") {
			t.Errorf("%+v: status = %s (%s), want ok with nothing checked", entry, finding.Status, finding.Detail)
		}
	}
}

func TestAnUndeclaredEntryIsNotADerivedOne(t *testing.T) {
	finding := findingFor(t, derivedReport(config.BlockedPath{Path: "/etc/luks/volume.key"}), "derived paths")
	if finding.Status != StatusOK || !strings.Contains(finding.Detail, "no derived") {
		t.Errorf("status = %s (%s), want ok with nothing to check", finding.Status, finding.Detail)
	}
}
