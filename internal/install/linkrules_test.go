package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
)

// It has to survive rendering, not merely be returned: these files are what
// actually refuses the read.
func TestALinkedPathReachesTheRenderedAccountFiles(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt("/home/operator/.config/gh/hosts.yml")

	for _, asset := range []string{"agent/claude/settings.json", "agent/permissions.json.tmpl"} {
		body, err := agentcfg.RenderAccount(asset, layout)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		if !strings.Contains(string(body), "/home/operator/.config/gh/hosts.yml") {
			t.Errorf("%s does not refuse the linked path", asset)
		}
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

	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
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

	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
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
	body, err := agentcfg.Render("etc/config.toml.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "[[secret.link]]") {
		t.Errorf("an install with no links rendered a link section:\n%s", body)
	}
}

// -- the doctor check -------------------------------------------------------

// A linked path under a home is what these actually are, so the rendering has
// to survive one that needs no escaping and one that does.
func TestALinkedPathIsQuotedIntoJSON(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt(filepath.Join("/home/operator", `odd"name`, "token"))

	body, err := agentcfg.RenderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentcfg.RuleEntries(body); err != nil {
		t.Errorf("a linked path broke the rendered JSON: %v", err)
	}
}

// A rule naming a longer path must not vouch for a shorter one: with both
// ~/.npmrc and ~/.npmrc-work linked, a rule covering only the second would
// otherwise report the first as refused while the agent can still read it.
func TestALongerPathDoesNotCoverAShorterOne(t *testing.T) {
	entries := map[string]bool{"Read(/home/operator/.npmrc-work)": true}
	if agentcfg.Named(entries, "/home/operator/.npmrc") {
		t.Error("a longer sibling was accepted as covering the shorter path")
	}
	if !agentcfg.Named(entries, "/home/operator/.npmrc-work") {
		t.Error("the path the rule actually names was not matched")
	}
	// Each agent wraps a path its own way, and all of those still match.
	for _, entry := range []string{
		"Read(/home/operator/.npmrc)", "Edit(/home/operator/.npmrc)",
		"/home/operator/.npmrc",
	} {
		if !agentcfg.Named(map[string]bool{entry: true}, "/home/operator/.npmrc") {
			t.Errorf("%q was not read as naming the path", entry)
		}
	}
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
			run := &runner{opts: opts, layout: layout, fs: hostfs.FS{}}
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
