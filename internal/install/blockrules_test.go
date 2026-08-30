package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func refusedAt(paths ...string) []config.BlockedPath {
	out := make([]config.BlockedPath, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.BlockedPath{Path: path})
	}
	return out
}

// The rule is the entire content of a [[secret.block]] entry, so an entry that
// does not reach the rules does nothing whatsoever.
func TestARefusedPathIsRefusedToClaudeAndThePluginHosts(t *testing.T) {
	layout := testLayout()
	layout.Blocked = refusedAt("/etc/luks/volume.key")

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
		t.Error("the plugin hosts' patterns do not carry the blocked path")
	}
}

// Rendering is what actually refuses the read, so being in the returned list is
// not enough.
func TestARefusedPathReachesTheRenderedAccountFiles(t *testing.T) {
	layout := testLayout()
	layout.Blocked = refusedAt("/etc/luks/volume.key")

	for _, asset := range []string{"agent/claude/settings.json", "agent/permissions.json.tmpl"} {
		body, err := renderAccount(asset, layout)
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
	layout.Blocked = refusedAt(dir)

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
	layout.Blocked = refusedAt(absent)

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
	layout.Blocked = refusedAt(dir)

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
	layout.Blocked = refusedAt("/etc/luks/volume.key")

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
	got := blockedRulePaths(Layout{Blocked: refusedAt("/b", "", "/a", "/b")})
	if !slices.Equal(got, []string{"/a", "/b"}) {
		t.Errorf("blockedRulePaths = %v, want the two paths sorted and deduplicated", got)
	}
}

// An install with no blocked paths renders what it always did.
func TestNoRefusedPathsChangeNothing(t *testing.T) {
	layout := testLayout()
	if !slices.Equal(claudeRules(layout), claudeRules(Layout{
		ConfigDir: layout.ConfigDir, LogDir: layout.LogDir, LibexecDir: layout.LibexecDir,
		BrokerUser: layout.BrokerUser, KeeperUser: layout.KeeperUser,
		ExecUser: layout.ExecUser,
	})) {
		t.Error("a layout with no blocked paths renders different rules")
	}
}

// The round trip that makes config.toml the entries' home: init renders them
// into the file it rewrites every run and reads them back on the next. Either
// half alone would erase them, and erasing them drops the deny rules.
//
// Every form, because the template writes one branch per form and a form with
// no branch is written as another form's empty key: the command branch was
// missing, so `block add --command` rendered `path = ""` and produced a config
// that would not load. A test that wrote its own TOML said the loader reads
// the key, which was true and was not the question.
func TestEveryBlockedFormRoundTripsThroughTheRenderedConfig(t *testing.T) {
	layout := testLayout()
	layout.Blocked = []config.BlockedPath{
		{Path: "/etc/luks/volume.key"},
		{Path: "/home/operator/.ssh"},
		{Command: "op read"},
		{Command: "sops -d"},
	}

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
	back, err := config.BaseBlocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(layout.Blocked) {
		t.Fatalf("read back %d entries, want %d:\n%s", len(back), len(layout.Blocked), body)
	}
	for i, want := range layout.Blocked {
		if back[i] != want {
			t.Errorf("entry %d read back as %+v, want %+v", i, back[i], want)
		}
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
	blockedPathsCheck.report(&report, "blocked paths", home, []string{"/etc/luks/volume.key"})

	finding := findingFor(t, report, "blocked paths")
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
	blockedPathsCheck.report(&report, "blocked paths", home, []string{"/etc/luks/volume.key"})

	finding := findingFor(t, report, "blocked paths")
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
	blockedPathsCheck.report(&report, "blocked paths", t.TempDir(), []string{"/etc/luks/volume.key"})

	finding := findingFor(t, report, "blocked paths")
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
	blockedPathsCheck.report(&report, "blocked paths", home, []string{absent})

	finding := findingFor(t, report, "blocked paths")
	if finding.Status != StatusOK {
		t.Errorf("a rule for a path that is not there was reported as %v: %s",
			finding.Status, finding.Detail)
	}
}

func TestDoctorSaysSoWhenNothingIsRefused(t *testing.T) {
	var report DoctorReport
	diagnoseBlockedPaths(&report, DoctorOptions{}, &config.Config{})

	finding := findingFor(t, report, "blocked paths")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// A blocked path is only ever a rule, so drift telling the operator to delete
// one is drift telling them to undo the entry. The drift check renders what
// faramir would write and calls anything else stale, so that render has to
// carry the blocked paths as well as the linked ones.
//
// The path ends in .key, which looksManaged matches, so a finding would name it.
func TestARefusedPathIsNotReportedAsDriftToRemove(t *testing.T) {
	dir := t.TempDir()
	body := "[command]\ntimeout_sec = 600\n\n[[secret.block]]\n" +
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
		t.Errorf("a blocked path was reported as a rule to remove, which would "+
			"undo the entry: %s", finding.Detail)
	}
}

func TestAPathRuleDoesNotCoverANameItEndsWith(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/home/operator/proj/.env)",
	    "Edit(/home/operator/proj/.env)"
	  ]}
	}`)
	var report DoctorReport
	blockedPathsCheck.report(&report, "blocked paths", home, []string{".env"})

	finding := findingFor(t, report, "blocked paths")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: a rule for one .env vouched for the "+
			"name entry that refuses every .env: %s", finding.Status, finding.Detail)
	}
}

func TestAgentCodeReportsAGuttedPlugin(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()
	rel := ".config/opencode/plugin/faramir.js"
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("export default {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	reportAgentCode(&report, home, configDir)
	finding := findingFor(t, report, "agent code")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed for a gutted plugin: %s", finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, rel) {
		t.Errorf("the failure does not name the file: %s", finding.Detail)
	}

	// The render itself passes: what init writes is what carries.
	ours, err := renderData("agent/plugin.js.tmpl", pluginData{
		BinDir: DefaultBinDir, Agent: "opencode", Path: rel, Layout: ruleLayout(configDir),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, ours, 0o640); err != nil {
		t.Fatal(err)
	}
	report = DoctorReport{}
	reportAgentCode(&report, home, configDir)
	finding = findingFor(t, report, "agent code")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK for the rendered plugin: %s", finding.Status, finding.Detail)
	}
}

// perInstallPaths is the entries and nothing else. The install's own
// directories are rendered beside it as subtree rules, so adding them here
// writes a second, differently shaped rule for each of them into every agent's
// file, and nothing downstream compares the set it was given.
func TestPerInstallPathsIsTheEntriesAlone(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt("/etc/luks/volume.key")
	layout.Blocked = refusedAt("/srv/keys/api.pem", "/etc/luks/volume.key")

	want := []string{"/etc/luks/volume.key", "/srv/keys/api.pem"}
	if got := perInstallPaths(layout); !slices.Equal(got, want) {
		t.Errorf("perInstallPaths = %v, want the entries sorted and deduplicated "+
			"across the two forms: %v", got, want)
	}
}
