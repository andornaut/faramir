package doctor

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
)

// The one check that can see a command entry. The blocked paths check compares
// against the agents' rule files, where a command never appears, so without
// this a declared command refused by nothing reads as a converged host: which
// is what it did while `block add` was not rendering the guard's file.
func TestDoctorSeesACommandMissingFromTheGuardsFile(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\ncommand = \"op read\"\n")
	libexec := t.TempDir()
	path := filepath.Join(libexec, "deny-patterns.txt")
	opts := Options{ConfigDir: dir}

	// A file rendered without the entry, which is what an add that wrote the
	// config and stopped leaves behind.
	if err := os.WriteFile(path, []byte(regexp.QuoteMeta(dir)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var missing Report
	reportDenyPatterns(&missing, opts, path)
	if len(missing.Findings) != 1 || missing.Findings[0].Status != StatusFailed {
		t.Fatalf("findings = %+v, want one failure", missing.Findings)
	}
	if !strings.Contains(missing.Findings[0].Detail, "op read") {
		t.Errorf("the finding does not name the command: %s", missing.Findings[0].Detail)
	}

	// And the file this install would actually write, which carries the command
	// among everything else it renders.
	rendered, err := agentcfg.RenderDenyPatterns(agentcfg.RuleLayout(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), agentcfg.BlockedCommandRule("op read")) {
		t.Fatal("the render does not carry the declared command")
	}
	if err := os.WriteFile(path, rendered, 0o644); err != nil {
		t.Fatal(err)
	}
	var present Report
	reportDenyPatterns(&present, opts, path)
	if len(present.Findings) != 1 || present.Findings[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one ok", present.Findings)
	}

	// A rule nobody renders is untidy rather than unguarded, so it warns.
	if err := os.WriteFile(path, append(rendered, []byte("\n\\bleftover\\b\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	var spare Report
	reportDenyPatterns(&spare, opts, path)
	if len(spare.Findings) != 1 || spare.Findings[0].Status != StatusWarn {
		t.Errorf("findings = %+v, want one warning", spare.Findings)
	}
}

// The hook skips a rule it cannot compile rather than failing every command
// over one typo, which is right there and leaves the loss silent: what should
// have been four rules is however many of them compiled. A re-render cannot
// notice, comparing the file against itself, so the check compiles each rule
// before it compares. Without this, an entry that split a rule across two lines
// took every path protection with it and doctor reported ok.
func TestDoctorFailsOnARenderedRuleThatWillNotCompile(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "[secret]\n")
	path := filepath.Join(t.TempDir(), "deny-patterns.txt")
	opts := Options{ConfigDir: dir}

	rendered, err := agentcfg.RenderDenyPatterns(agentcfg.RuleLayout(dir))
	if err != nil {
		t.Fatal(err)
	}
	// What this install renders, which must pass, and the same with one rule
	// broken the way a split leaves both halves.
	if err := os.WriteFile(path, rendered, 0o644); err != nil {
		t.Fatal(err)
	}
	var clean Report
	reportDenyPatterns(&clean, opts, path)
	if len(clean.Findings) != 1 || clean.Findings[0].Status != StatusOK {
		t.Fatalf("a file this install rendered was not ok: %+v", clean.Findings)
	}

	if err := os.WriteFile(path, append(rendered, "\n((unbalanced\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	var broken Report
	reportDenyPatterns(&broken, opts, path)
	if len(broken.Findings) != 1 || broken.Findings[0].Status != StatusFailed {
		t.Fatalf("findings = %+v, want one failure", broken.Findings)
	}
	for _, want := range []string{"will not compile", "refuses nothing"} {
		if !strings.Contains(broken.Findings[0].Detail, want) {
			t.Errorf("the finding does not say %q: %s", want, broken.Findings[0].Detail)
		}
	}
}

func TestDoctorPassesWhenARefusedPathIsRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/etc/luks/volume.key)",
	    "Edit(/etc/luks/volume.key)"
	  ]}
	}`)
	var report Report
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
	var report Report
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
	var report Report
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
	var report Report
	blockedPathsCheck.report(&report, "blocked paths", home, []string{absent})

	finding := findingFor(t, report, "blocked paths")
	if finding.Status != StatusOK {
		t.Errorf("a rule for a path that is not there was reported as %v: %s",
			finding.Status, finding.Detail)
	}
}

func TestDoctorSaysSoWhenNothingIsRefused(t *testing.T) {
	var report Report
	diagnoseBlockedPaths(&report, Options{}, &config.Config{})

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

	var report Report
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
	var report Report
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

	var report Report
	reportAgentCode(&report, home, configDir)
	finding := findingFor(t, report, "agent code")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed for a gutted plugin: %s", finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, rel) {
		t.Errorf("the failure does not name the file: %s", finding.Detail)
	}

	// The render itself passes: what init writes is what carries.
	ours, err := agentcfg.RenderData("agent/plugin.js.tmpl", agentcfg.PluginData{
		BinDir: hostlayout.DefaultBinDir, Agent: "opencode", Path: rel, Layout: agentcfg.RuleLayout(configDir),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, ours, 0o640); err != nil {
		t.Fatal(err)
	}
	report = Report{}
	reportAgentCode(&report, home, configDir)
	finding = findingFor(t, report, "agent code")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK for the rendered plugin: %s", finding.Status, finding.Detail)
	}
}
