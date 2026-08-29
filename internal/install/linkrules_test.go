package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// A linked value joins the redactor, so the file it comes out of has to stop
// being one the agent can simply read.
func TestALinkedPathIsRefusedToClaudeAndThePluginHosts(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt("/home/operator/.config/gh/hosts.yml")

	rules := claudeRules(layout)
	for _, want := range []string{
		"Read(/home/operator/.config/gh/hosts.yml)",
		"Edit(/home/operator/.config/gh/hosts.yml)",
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the Claude rules do not carry %q", want)
		}
	}
	if !slices.Contains(pluginPatterns(layout), "/home/operator/.config/gh/hosts.yml") {
		t.Error("the plugin hosts' patterns do not carry the linked path")
	}
}

// It has to survive rendering, not merely be returned: these files are what
// actually refuses the read.
func TestALinkedPathReachesTheRenderedAccountFiles(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt("/home/operator/.config/gh/hosts.yml")

	for _, asset := range []string{"agent/claude/settings.json", "agent/permissions.json.tmpl"} {
		body, err := renderAccount(asset, layout)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		if !strings.Contains(string(body), "/home/operator/.config/gh/hosts.yml") {
			t.Errorf("%s does not refuse the linked path", asset)
		}
	}
}

// An empty entry would be a prefix of every path in the plugin hosts' spelling,
// so it is dropped rather than rendered: that fails closed and still breaks the
// agent. Duplicates and order are settled so the file does not churn.
func TestLinkedPathsAreCleanedAndOrdered(t *testing.T) {
	got := linkedPaths(Layout{Links: linksAt("/b", "", "/a", "/b")})
	if !slices.Equal(got, []string{"/a", "/b"}) {
		t.Errorf("linkedPaths = %v, want the two paths sorted and deduplicated", got)
	}
}

// An install with no links renders what it always did.
func TestNoLinksChangesNothing(t *testing.T) {
	layout := testLayout()
	if !slices.Equal(claudeRules(layout), claudeRules(Layout{
		ConfigDir: layout.ConfigDir, LogDir: layout.LogDir, LibexecDir: layout.LibexecDir,
		BrokerUser: layout.BrokerUser, KeeperUser: layout.KeeperUser,
		ExecUser: layout.ExecUser,
	})) {
		t.Error("a layout with no links renders different rules")
	}
}

// The round trip that makes config.toml the links' home: init renders them into
// the file it rewrites every run, and reads them back out of it on the next.
// Either half alone would erase them.
func TestLinksRoundTripThroughTheRenderedConfig(t *testing.T) {
	layout := testLayout()
	layout.Links = []config.Link{
		{Ref: "gh/token", Path: "/home/operator/.config/gh/hosts.yml",
			Type: "yaml", Key: "github.com/oauth_token"},
		{Ref: "host/luks", Path: "/home/operator/.private/keyfile", Type: "base64"},
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
	got, err := config.BaseLinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, layout.Links) {
		t.Errorf("links = %+v, want %+v", got, layout.Links)
	}
}

// A whole-file type renders no key, which is what the loader requires: a key
// there is refused, so rendering an empty one would produce a config that does
// not load.
func TestAWholeFileLinkRendersNoKey(t *testing.T) {
	layout := testLayout()
	layout.Links = []config.Link{{Ref: "host/luks", Path: "/x", Type: "text"}}

	body, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// Read back rather than grepped: `[ssh] key` is in this file too, so the
	// question is what the entry carries, not what the text contains.
	links, err := config.BaseLinks(path)
	if err != nil {
		t.Fatalf("the rendered config does not load: %v\n%s", err, body)
	}
	if len(links) != 1 || links[0].Key != "" {
		t.Errorf("links = %+v, want one entry with no key", links)
	}
}

// An install with no links renders the config it always did.
func TestNoLinksRendersNoSection(t *testing.T) {
	body, err := render("etc/config.toml.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "[[secret.link]]") {
		t.Errorf("an install with no links rendered a link section:\n%s", body)
	}
}

// -- the doctor check -------------------------------------------------------

func TestDoctorPassesWhenALinkedFileIsRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/home/operator/.config/gh/hosts.yml)",
	    "Edit(/home/operator/.config/gh/hosts.yml)"
	  ]}
	}`)
	var report DoctorReport
	linkedFilesCheck.report(&report, "linked files", home, []string{"/home/operator/.config/gh/hosts.yml"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// The state this check exists for: a link in the config whose path the deny
// rules do not name, which is a value in the redactor whose plaintext the agent
// can still open.
func TestDoctorFailsWhenALinkedFileIsNotRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(**/*.key)"]}
	}`)
	var report DoctorReport
	linkedFilesCheck.report(&report, "linked files", home, []string{"/home/operator/.npmrc"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: %s", finding.Status, finding.Detail)
	}
	for _, want := range []string{"/home/operator/.npmrc", "faramir init"} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("the finding does not name %q: %s", want, finding.Detail)
		}
	}
}

// Nothing to compare against is not a pass. An account with no rule file
// refuses nothing, and reporting OK would say the opposite.
func TestDoctorDoesNotClaimCoverageWithNoRuleFile(t *testing.T) {
	var report DoctorReport
	linkedFilesCheck.report(&report, "linked files", t.TempDir(), []string{"/home/operator/.npmrc"})

	finding := findingFor(t, report, "linked files")
	if finding.Status == StatusOK {
		t.Errorf("an account with no rule file was reported as covered: %s", finding.Detail)
	}
}

func TestDoctorSaysSoWhenNothingIsLinked(t *testing.T) {
	var report DoctorReport
	diagnoseLinkedFiles(&report, DoctorOptions{}, &config.Config{})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// findingFor is the one finding a check reported, or a failure naming what was
// there instead.
func findingFor(t *testing.T, report DoctorReport, name string) Finding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Name == name {
			return finding
		}
	}
	t.Fatalf("no %q finding in %+v", name, report.Findings)
	return Finding{}
}

// A linked path under a home is what these actually are, so the rendering has
// to survive one that needs no escaping and one that does.
func TestALinkedPathIsQuotedIntoJSON(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt(filepath.Join("/home/operator", `odd"name`, "token"))

	body, err := renderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ruleEntries(body); err != nil {
		t.Errorf("a linked path broke the rendered JSON: %v", err)
	}
}

// A rule naming a longer path must not vouch for a shorter one: with both
// ~/.npmrc and ~/.npmrc-work linked, a rule covering only the second would
// otherwise report the first as refused while the agent can still read it.
func TestALongerPathDoesNotCoverAShorterOne(t *testing.T) {
	entries := map[string]bool{"Read(/home/operator/.npmrc-work)": true}
	if named(entries, "/home/operator/.npmrc") {
		t.Error("a longer sibling was accepted as covering the shorter path")
	}
	if !named(entries, "/home/operator/.npmrc-work") {
		t.Error("the path the rule actually names was not matched")
	}
	// Each agent wraps a path its own way, and all of those still match.
	for _, entry := range []string{
		"Read(/home/operator/.npmrc)", "Edit(/home/operator/.npmrc)",
		"/home/operator/.npmrc",
	} {
		if !named(map[string]bool{entry: true}, "/home/operator/.npmrc") {
			t.Errorf("%q was not read as naming the path", entry)
		}
	}
}

// The drift report renders what faramir writes now and reports the difference
// as rules to delete. Without the linked paths in that render, every rule the
// links put there reads as one faramir has stopped writing, and the operator is
// told to remove the rules the check beside it demands.
func TestALinkedPathIsNotReportedAsStaleDrift(t *testing.T) {
	dir := t.TempDir()
	body := "[command]\ntimeout_sec = 600\n\n[[secret.link]]\n" +
		"ref = \"aws/secret\"\npath = \"/home/operator/.aws/credentials\"\n" +
		"type = \"ini\"\nkey = \"default/aws_secret_access_key\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// "credentials" is in protectedPaths, so looksManaged calls this faramir's
	// and the finding would name it.
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/home/operator/.aws/credentials)",
	    "Edit(/home/operator/.aws/credentials)"
	  ]}
	}`)

	var report DoctorReport
	reportRuleDrift(&report, home, dir)

	finding := findingFor(t, report, "agent rule drift")
	if strings.Contains(finding.Detail, "/home/operator/.aws/credentials") {
		t.Errorf("a linked path was reported as a rule to remove: %s", finding.Detail)
	}
}

// linksAt is one link per path, for the tests that care only about which paths
// the rules refuse.
func linksAt(paths ...string) []config.Link {
	out := make([]config.Link, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.Link{Ref: "test", Path: path, Type: "text"})
	}
	return out
}

// A value the loader refuses must never reach the file. Writing it is what
// makes it unrecoverable: the daemons will not start, and `faramir init`
// refuses to run against a config it cannot parse, so the command that would
// repair it is the one that is blocked.
//
// Every flag states its range in its own help, and this is what enforces them:
// the ranges live in the loader, and a second copy in the installer would be a
// second thing to keep in step.
func TestAConfigThatWouldNotLoadIsNotWritten(t *testing.T) {
	for name, opts := range map[string]Options{
		"a ceiling below the default":    {CommandTimeoutSec: 600, CommandMaxTimeoutSec: 300},
		"an escalation past its ceiling": {SudoTimeoutSec: config.MaxSudoTimeoutSec + 1, AllowSudo: true},
		"a length under the floor":       {SecretMinLength: 2},
		"an env name that is not one":    {CommandEnv: map[string]string{"MY VAR": "1"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := installDir(t)
			existing := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(existing, []byte("# the install that was here\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			opts.ConfigDir, opts.AgentUser = dir, "operator"
			opts.applyDefaults()
			layout, err := opts.layout()
			if err != nil {
				t.Fatal(err)
			}
			run := &runner{opts: opts, layout: layout, fs: fsys{}}
			if err := run.stepConfig(); err == nil {
				t.Error("the config was written")
			}
			body, err := os.ReadFile(existing)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "# the install that was here\n" {
				t.Errorf("the install that was there was replaced:\n%s", body)
			}
		})
	}
}
