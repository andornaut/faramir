package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func refusedAt(paths ...string) []config.RefusedPath {
	out := make([]config.RefusedPath, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.RefusedPath{Path: path})
	}
	return out
}

// The rule is the entire content of a [[secret.refuse]] entry, so an entry that
// does not reach the rules does nothing whatsoever.
func TestARefusedPathIsRefusedToClaudeAndThePluginHosts(t *testing.T) {
	layout := testLayout()
	layout.Refused = refusedAt("/etc/luks/volume.key")

	rules := claudeRules(layout)
	for _, want := range []string{
		"Read(/etc/luks/volume.key)",
		"Edit(/etc/luks/volume.key)",
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the Claude rules do not carry %q", want)
		}
	}
	if !slices.Contains(pluginPatterns(layout), "/etc/luks/volume.key") {
		t.Error("the plugin hosts' patterns do not carry the refused path")
	}
}

// Rendering is what actually refuses the read, so being in the returned list is
// not enough.
func TestARefusedPathReachesTheRenderedAccountFiles(t *testing.T) {
	layout := testLayout()
	layout.Refused = refusedAt("/etc/luks/volume.key")

	for _, asset := range []string{"agent/claude/settings.json", "agent/permissions.json.tmpl"} {
		body, err := render(asset, layout)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		if !strings.Contains(string(body), "/etc/luks/volume.key") {
			t.Errorf("%s does not refuse the path", asset)
		}
	}
}

// A directory has to be refused along with what is under it, or naming ~/.ssh
// would refuse the directory entry and leave every key in it readable.
func TestARefusedDirectoryCarriesWhatIsUnderIt(t *testing.T) {
	dir := t.TempDir()
	layout := testLayout()
	layout.Refused = refusedAt(dir)

	rules := claudeRules(layout)
	for _, want := range []string{"Read(" + dir + ")", "Read(" + dir + "/**)"} {
		if !slices.Contains(rules, want) {
			t.Errorf("the Claude rules do not carry %q", want)
		}
	}
	if !slices.Contains(pluginPatterns(layout), dir+"/*") {
		t.Error("the plugin hosts' patterns do not reach under the directory")
	}
}

// The case the feature is most often for: a key on a volume that is not
// mounted. The rules cannot depend on what is there now, because nothing
// re-renders them when it appears, so an entry added while the volume is away
// has to already cover what turns up inside it.
func TestAnAbsentRefusedPathStillCoversWhatAppearsUnderIt(t *testing.T) {
	absent := "/mnt/nothing-is-mounted-here/keys"
	layout := testLayout()
	layout.Refused = refusedAt(absent)

	rules := claudeRules(layout)
	for _, want := range []string{
		"Read(" + absent + ")",
		"Read(" + absent + "/**)",
		"Edit(" + absent + "/**)",
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the rules do not carry %q, so a key inside it is readable "+
				"once the volume mounts", want)
		}
	}
	if !slices.Contains(pluginPatterns(layout), absent+"/*") {
		t.Error("the plugin hosts' patterns do not reach under an absent path")
	}
}

// And the rules are the same whether the path is there or not, or the drift
// check re-renders a different set from the one that was written and reports
// the difference as rules to delete.
func TestRefusedRulesDoNotDependOnWhatIsOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	layout := testLayout()
	layout.Refused = refusedAt(dir)

	away := claudeRules(layout)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	there := claudeRules(layout)

	if !slices.Equal(away, there) {
		t.Errorf("the rules changed when the directory appeared:\nabsent:  %v\npresent: %v",
			away, there)
	}
}

// A path that is both linked and refused renders one rule, not two. The agent
// rule files are merged rather than replaced, so a duplicate written once is a
// duplicate nothing removes.
func TestAPathBothLinkedAndRefusedRendersOneRule(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt("/etc/luks/volume.key")
	layout.Refused = refusedAt("/etc/luks/volume.key")

	n := 0
	for _, rule := range claudeRules(layout) {
		if rule == "Read(/etc/luks/volume.key)" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Read(/etc/luks/volume.key) rendered %d times, want 1", n)
	}
}

// Duplicates and order are settled so the rule files do not churn, and an empty
// entry is dropped: in the plugin hosts' spelling it is a prefix of every path.
func TestRefusedPathsAreCleanedAndOrdered(t *testing.T) {
	got := refusedRulePaths(Layout{Refused: refusedAt("/b", "", "/a", "/b")})
	if !slices.Equal(got, []string{"/a", "/b"}) {
		t.Errorf("refusedRulePaths = %v, want the two paths sorted and deduplicated", got)
	}
}

// An install with no refused paths renders what it always did.
func TestNoRefusedPathsChangeNothing(t *testing.T) {
	layout := testLayout()
	if !slices.Equal(claudeRules(layout), claudeRules(Layout{
		ConfigDir: layout.ConfigDir, LogDir: layout.LogDir, LibexecDir: layout.LibexecDir,
	})) {
		t.Error("a layout with no refused paths renders different rules")
	}
}

// The round trip that makes config.toml the entries' home: init renders them
// into the file it rewrites every run and reads them back on the next. Either
// half alone would erase them, and erasing them drops the deny rules.
func TestRefusedPathsRoundTripThroughTheRenderedConfig(t *testing.T) {
	layout := testLayout()
	layout.Refused = refusedAt("/etc/luks/volume.key", "/home/operator/.ssh")

	body, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// It has to load as a whole, not merely contain the right text: an entry
	// rendered in the wrong place is a config no daemon can read.
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the rendered config does not load: %v\n%s", err, body)
	}
	back, err := config.BaseRefusedPaths(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 {
		t.Fatalf("read back %+v, want the two entries", back)
	}
	if back[0].Path != "/etc/luks/volume.key" || back[1].Path != "/home/operator/.ssh" {
		t.Errorf("read back %+v", back)
	}
}

// -- the doctor check -------------------------------------------------------

func TestDoctorPassesWhenARefusedPathIsRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/etc/luks/volume.key)",
	    "Edit(/etc/luks/volume.key)"
	  ]}
	}`)
	var report DoctorReport
	reportRefusedPaths(&report, home, []string{"/etc/luks/volume.key"})

	finding := findingFor(t, report, "refused paths")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// The state this check exists for: an entry in the config whose path the deny
// rules do not name. A link that goes unrefused still has its value redacted;
// this one has nothing at all, the rule being all it ever was.
func TestDoctorFailsWhenARefusedPathIsNotRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(**/*.pem)"]}
	}`)
	var report DoctorReport
	reportRefusedPaths(&report, home, []string{"/etc/luks/volume.key"})

	finding := findingFor(t, report, "refused paths")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: %s", finding.Status, finding.Detail)
	}
	for _, want := range []string{"/etc/luks/volume.key", "faramir init"} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("the finding does not name %q: %s", want, finding.Detail)
		}
	}
}

// Nothing to compare against is not a pass: an account with no rule file
// refuses nothing, and reporting OK would say the opposite.
func TestDoctorDoesNotClaimARefusedPathIsCoveredWithNoRuleFile(t *testing.T) {
	var report DoctorReport
	reportRefusedPaths(&report, t.TempDir(), []string{"/etc/luks/volume.key"})

	finding := findingFor(t, report, "refused paths")
	if finding.Status == StatusOK {
		t.Errorf("an account with no rule file was reported as covered: %s", finding.Detail)
	}
}

// A path that is not there is still covered by its rule, so the check does not
// look at the filesystem: an unmounted volume must not read as a fault.
func TestDoctorDoesNotAskWhetherARefusedPathExists(t *testing.T) {
	absent := "/mnt/nothing-is-mounted-here/luks.key"
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(`+absent+`)"]}
	}`)
	var report DoctorReport
	reportRefusedPaths(&report, home, []string{absent})

	finding := findingFor(t, report, "refused paths")
	if finding.Status != StatusOK {
		t.Errorf("a rule for a path that is not there was reported as %v: %s",
			finding.Status, finding.Detail)
	}
}

func TestDoctorSaysSoWhenNothingIsRefused(t *testing.T) {
	var report DoctorReport
	diagnoseRefusedPaths(&report, DoctorOptions{}, &config.Config{})

	finding := findingFor(t, report, "refused paths")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// A refused path is only ever a rule, so drift telling the operator to delete
// one is drift telling them to undo the entry. The drift check renders what
// faramir would write and calls anything else stale, so that render has to
// carry the refused paths as well as the linked ones.
//
// The path ends in .key, which looksManaged matches, so a finding would name it.
func TestARefusedPathIsNotReportedAsDriftToRemove(t *testing.T) {
	dir := t.TempDir()
	body := "[command]\ntimeout_sec = 600\n\n[[secret.refuse]]\n" +
		"path = \"/etc/luks/volume.key\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/etc/luks/volume.key)",
	    "Edit(/etc/luks/volume.key)"
	  ]}
	}`)

	var report DoctorReport
	reportRuleDrift(&report, home, dir)

	finding := findingFor(t, report, "agent rule drift")
	if strings.Contains(finding.Detail, "/etc/luks/volume.key") {
		t.Errorf("a refused path was reported as a rule to remove, which would "+
			"undo the entry: %s", finding.Detail)
	}
}
