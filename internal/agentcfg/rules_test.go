package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/configtest"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
)

// claudeRule is what claudeRules renders for one pattern: the verb around the
// filesystem-root anchor. Written once so a test names the path it is about
// and not the anchoring, which TestTheClaudeRulesAreAnchoredAtTheRoot covers.
func claudeRule(verb, pattern string) string {
	return verb + "(//" + strings.TrimPrefix(pattern, "/") + ")"
}

// Every Claude Code rule is anchored at the filesystem root. One leading slash
// anchors at the settings source instead, and a bare `**/` pattern at the
// working directory, so either spelling leaves a declared path readable from
// anywhere else.
func TestTheClaudeRulesAreAnchoredAtTheRoot(t *testing.T) {
	layout := layouttest.Layout()
	layout.Blocked = configtest.RefusedAt("/etc/luks/volume.key")

	for _, rule := range claudeRules(layout) {
		pattern := strings.TrimSuffix(strings.SplitN(rule, "(", 2)[1], ")")
		if !strings.HasPrefix(pattern, "//") {
			t.Errorf("%q is not anchored at the filesystem root", rule)
		}
	}
}

// The rule is the entire content of a [[secret.block]] entry, so an entry that
// does not reach the rules does nothing whatsoever.
func TestARefusedPathIsRefusedToClaudeAndThePluginHosts(t *testing.T) {
	layout := layouttest.Layout()
	layout.Blocked = configtest.RefusedAt("/etc/luks/volume.key")

	rules := claudeRules(layout)
	for _, want := range []string{
		claudeRule("Read", "/etc/luks/volume.key"),
		claudeRule("Edit", "/etc/luks/volume.key"),
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the Claude rules do not carry %q", want)
		}
	}
	if !slices.Contains(pluginPatterns(layout), "/etc/luks/volume.key") {
		t.Error("the plugin hosts' patterns do not carry the blocked path")
	}
}

// A directory has to be refused along with what is under it, or naming ~/.ssh
// would refuse the directory entry and leave every key in it readable.
func TestARefusedDirectoryCarriesWhatIsUnderIt(t *testing.T) {
	dir := t.TempDir()
	layout := layouttest.Layout()
	layout.Blocked = configtest.RefusedAt(dir)

	rules := claudeRules(layout)
	for _, want := range []string{claudeRule("Read", dir), claudeRule("Read", dir+"/**")} {
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
	layout := layouttest.Layout()
	layout.Blocked = configtest.RefusedAt(absent)

	rules := claudeRules(layout)
	for _, want := range []string{
		claudeRule("Read", absent),
		claudeRule("Read", absent+"/**"),
		claudeRule("Edit", absent+"/**"),
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
	layout := layouttest.Layout()
	layout.Blocked = configtest.RefusedAt(dir)

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
	layout := layouttest.Layout()
	layout.Links = configtest.LinksAt("/etc/luks/volume.key")
	layout.Blocked = configtest.RefusedAt("/etc/luks/volume.key")

	want := claudeRule("Read", "/etc/luks/volume.key")
	n := 0
	for _, rule := range claudeRules(layout) {
		if rule == want {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%s rendered %d times, want 1", want, n)
	}
}

// Duplicates and order are settled so the rule files do not churn, and an empty
// entry is dropped: in the plugin hosts' spelling it is a prefix of every path.
func TestRefusedPathsAreCleanedAndOrdered(t *testing.T) {
	got := blockedRulePaths(hostlayout.Layout{Blocked: configtest.RefusedAt("/b", "", "/a", "/b")})
	if !slices.Equal(got, []string{"/a", "/b"}) {
		t.Errorf("blockedRulePaths = %v, want the two paths sorted and deduplicated", got)
	}
}

// An install with no blocked paths renders what it always did.
func TestNoRefusedPathsChangeNothing(t *testing.T) {
	layout := layouttest.Layout()
	if !slices.Equal(claudeRules(layout), claudeRules(hostlayout.Layout{
		ConfigDir: layout.ConfigDir, LogDir: layout.LogDir, LibexecDir: layout.LibexecDir,
		BrokerUser: layout.BrokerUser, KeeperUser: layout.KeeperUser,
		ExecUser: layout.ExecUser,
	})) {
		t.Error("a layout with no blocked paths renders different rules")
	}
}

// A linked value joins the redactor, so the file it comes out of has to stop
// being one the agent can simply read.
func TestALinkedPathIsRefusedToClaudeAndThePluginHosts(t *testing.T) {
	layout := layouttest.Layout()
	layout.Links = configtest.LinksAt("/home/operator/.config/gh/hosts.yml")

	rules := claudeRules(layout)
	for _, want := range []string{
		claudeRule("Read", "/home/operator/.config/gh/hosts.yml"),
		claudeRule("Edit", "/home/operator/.config/gh/hosts.yml"),
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the Claude rules do not carry %q", want)
		}
	}
	if !slices.Contains(pluginPatterns(layout), "/home/operator/.config/gh/hosts.yml") {
		t.Error("the plugin hosts' patterns do not carry the linked path")
	}
}

// An empty entry would be a prefix of every path in the plugin hosts' spelling,
// so it is dropped rather than rendered: that fails closed and still breaks the
// agent. Duplicates and order are settled so the file does not churn.
func TestLinkedPathsAreCleanedAndOrdered(t *testing.T) {
	got := linkedPaths(hostlayout.Layout{Links: configtest.LinksAt("/b", "", "/a", "/b")})
	if !slices.Equal(got, []string{"/a", "/b"}) {
		t.Errorf("linkedPaths = %v, want the two paths sorted and deduplicated", got)
	}
}

// An install with no links renders what it always did.
func TestNoLinksChangesNothing(t *testing.T) {
	layout := layouttest.Layout()
	if !slices.Equal(claudeRules(layout), claudeRules(hostlayout.Layout{
		ConfigDir: layout.ConfigDir, LogDir: layout.LogDir, LibexecDir: layout.LibexecDir,
		BrokerUser: layout.BrokerUser, KeeperUser: layout.KeeperUser,
		ExecUser: layout.ExecUser,
	})) {
		t.Error("a layout with no links renders different rules")
	}
}

// A credential faramir neither writes nor reads is the operator's to declare,
// so nothing is compiled in and a bare install does not block it.
func TestTheRelocatedRulesAreGone(t *testing.T) {
	reads := func(layout hostlayout.Layout, path string) bool {
		for _, rule := range commandRules(layout) {
			if regexp.MustCompile("(?i)" + rule).MatchString("cat " + path) {
				return true
			}
		}
		return false
	}

	bare := hostlayout.Layout{}
	for _, path := range relocated {
		if reads(bare, path) {
			t.Errorf("%s is refused by a built-in rule, which was relocated", path)
		}
	}

	// And they are refusable by declaring them, which is where they went. A path
	// covers the hierarchy under it, so the directory answers for every key in
	// it rather than for the names somebody thought to list.
	declared := hostlayout.Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
		{Path: "/home/op/.ssh"},
		{Path: "/srv/tls"},
		{Path: "/srv/app/.env"},
	}}
	for _, path := range []string{
		"/home/op/.ssh/id_rsa",
		// The name no list would have carried, which is the case a path covers
		// and an enumeration of file names does not.
		"/home/op/.ssh/identity",
		"/srv/tls/chain.pem",
		"/srv/app/.env",
	} {
		if !reads(declared, path) {
			t.Errorf("%s is not refused by the entry that declares it", path)
		}
	}
}

// Nothing about this install is compiled into the rules: every path it writes
// is rendered as a literal out of the layout, so a host that moved one is
// refused where the file actually is rather than where the default would have
// put it. An install that took --config-dir is the case this covers, and the
// defaults are asserted absent as well as the literals present: a rule holding
// both refuses the right path and somebody else's at the same time.
func TestTheInstallsOwnPathsAreRefusedAsLiterals(t *testing.T) {
	// Every directory moved off its default, so a rule carrying a default is a
	// rule that was compiled in rather than rendered.
	layout := hostlayout.Layout{
		ConfigDir:  "/opt/faramir",
		LogDir:     "/srv/log/faramir",
		LibexecDir: "/opt/faramir/libexec",
	}
	rules := claudeRules(layout)
	for _, want := range []string{
		claudeRule("Read", "/opt/faramir/**"),         // the age key, the SSH key, config.toml
		claudeRule("Read", "/opt/faramir/secrets/**"), // the managed sops files
		claudeRule("Read", "/srv/log/faramir/**"),     // the audit log
		claudeRule("Read", "/opt/faramir/libexec/**"), // wrap.sh and the guard
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the rules do not carry %q", want)
		}
	}
	// And not the defaults beside them: a rule naming where the file would have
	// been refuses a path on somebody else's host and leaves this one open.
	for _, unwanted := range []string{
		claudeRule("Read", hostlayout.DefaultConfigDir+"/**"),
		claudeRule("Read", hostlayout.DefaultLogDir+"/**"),
		claudeRule("Read", hostlayout.DefaultLibexecDir+"/**"),
	} {
		if slices.Contains(rules, unwanted) {
			t.Errorf("the rules carry %q, which this layout moved", unwanted)
		}
	}
}

// Where a declared command is matched: at a command position, not wherever the
// words happen to appear. The difference is whether an entry is safe to write
// at all, or safe only if it is long enough that no flag on any host carries
// it, which is not a question an operator can answer about a fleet.
func TestADeclaredCommandIsMatchedAtACommandPosition(t *testing.T) {
	layout := hostlayout.Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
		{Command: "op read"}, {Command: "pass"},
	}}
	rules := commandRules(layout)
	for _, tc := range []struct {
		command string
		denied  bool
		why     string
	}{
		{"op read op://v/i/f", true, "the command itself"},
		{"  op read x", true, "after leading whitespace"},
		{"foo; op read x", true, "after a separator"},
		{"foo && op read x", true, "after a conditional"},
		{"foo | op read x", true, "after a pipe"},
		{"(op read x)", true, "in a subshell"},
		{"sudo op read x", true, "behind sudo"},
		{"sudo -u me op read x", true, "behind sudo with a flag that takes an argument"},
		{"sudo -n op read x", true, "and one that does not"},
		{"sudo nice op read x", true, "two prefixes deep"},
		{"env FOO=1 op read x", true, "behind env"},
		{"FOO=1 op read x", true, "behind a bare assignment"},
		{"sh -c 'op read x'", true, "inside a shell's command string"},
		{`bash -lc "op read x"`, true, "whichever shell and quote"},
		{"pass personal/router", true, "a one-word entry at a command position"},
		// The same command, spelled with the path the program is at. Without it
		// the spelling an agent reaches for after meeting the refusal is the one
		// that is not refused.
		{"/usr/bin/op read x", true, "named by absolute path"},
		{"./op read x", true, "named relative to the working directory"},
		{"sudo /usr/local/bin/op read x", true, "by path behind a prefix"},
		{"/usr/local/bin/pass personal/router", true, "a one-word entry by path"},

		{"grep -r 'op read' defaults.yml", false, "a search naming it is not running it"},
		{"echo op read", false, "and nor is echoing it"},
		{"ansible-playbook --ask-become-pass site.yml", false,
			"a flag carrying the word: the case a one-word entry could not be written for"},
		{"vim notes-op-read.md", false, "and a file named after it"},
		{"opera read", false, "a longer command starting the same way"},
		{"/usr/bin/opera read", false, "and by path it is still a different program"},
		{"cat /etc/op read", false, "the words as an argument, path or not"},
		{"vim /home/me/develop read", false, "a path ending in a word that is not one"},
		{"cat README.md", false, "ordinary work"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if denied := matchesAny(t, rules, tc.command); denied != tc.denied {
				t.Errorf("denied = %v, want %v: %s", denied, tc.denied, tc.why)
			}
		})
	}
}

// It reaches the command guard and nothing else: a command is not a path, so no
// agent's file-tool rules can carry one.
func TestADeclaredCommandReachesTheGuardAlone(t *testing.T) {
	layout := hostlayout.Layout{
		ConfigDir: "/etc/faramir",
		Blocked: []config.BlockedPath{
			{Command: "op read"},
			{Command: "sops -d"},
			{Path: "/srv/certs/server.pem"},
		},
	}
	rules := commandRules(layout)
	for _, tc := range []struct {
		command string
		denied  bool
		why     string
	}{
		{"op read op://vault/item/field", true, "the declared command"},
		{"sops -d secrets.sops.yml", true, "and the one with a flag in it"},
		{"sops   -d x.yml", true, "whitespace between the words is any run of it"},
		{"echo op read", false, "echoing the words is not running the command"},
		{"opera read", false, "a longer word starting the same way"},
		{"op readme", false, "and one ending it"},
		{"sops -e x.yml", false, "a different flag is a different command"},
		{"cat README.md", false, "ordinary work"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if denied := matchesAny(t, rules, tc.command); denied != tc.denied {
				t.Errorf("denied = %v, want %v: %s", denied, tc.denied, tc.why)
			}
		})
	}
	// The file-tool spellings carry the name and not the commands.
	for _, rule := range claudeRules(layout) {
		for _, word := range []string{"op", "sops"} {
			if rule == claudeRule("Read", "**/"+word) {
				t.Errorf("a command reached Claude Code's rules as %q", rule)
			}
		}
	}
}

// Antigravity's matcher takes one leading wildcard and nothing after it that
// crosses a separator. Every other shape refuses nothing at all, which is the
// failure this package is built to avoid: a rule that covers nothing reads
// exactly like one that covers everything.
func TestNoRuleIsWrittenInAShapeTheAgentMatchesNothingWith(t *testing.T) {
	layout := layouttest.Layout()
	layout.Blocked = []config.BlockedPath{
		{Path: "/home/op/.ssh"},
		{Path: "/mnt/vol/luks.key"},
		{Path: "/home/op/.config/sops/age"},
	}
	rules := agyRules(layout)
	for _, rule := range rules {
		target := rule[strings.Index(rule, "(")+1 : len(rule)-1]
		if strings.HasSuffix(target, "/*") {
			t.Errorf("%q ends in a trailing wildcard, which matches nothing here, "+
				"not even the files directly inside", rule)
		}
		if star := strings.Index(target, "*"); star >= 0 {
			if star != 0 {
				t.Errorf("%q has a wildcard that does not lead, so it matches nothing", rule)
			}
			if strings.Contains(target[star+1:], "/") {
				t.Errorf("%q puts a separator after the wildcard, so it matches nothing", rule)
			}
		}
	}

	// A literal path is named bare: a path covers the hierarchy under it, so the
	// directory is the whole rule.
	joined := strings.Join(rules, "\n")
	for _, want := range []string{"read_file(/home/op/.ssh)", "write_file(/mnt/vol/luks.key)"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s is missing:\n%s", want, joined)
		}
	}
}

// The rendered agent files are JSON, and Go's escape set is not JSON's.
//
// Every path in them is the operator's, from --config-dir or --ssh-key, and
// nothing on the way here refuses a control character in one. Rendered with
// Go's quoting, such a path produces a settings file the agent cannot parse:
// the enrolment reports success and every rule in that file is absent, which is
// the failure mode worth a test rather than the syntax error.
func TestTheRenderedAgentFilesAreParseableJSON(t *testing.T) {
	for _, awkward := range []string{
		"/etc/faramir",
		"/etc/far\amir",
		"/etc/far\vmir",
		"/etc/far\x01mir",
		"/etc/far\"mir",
		"/etc/far\\mir",
	} {
		t.Run(strconv.Quote(awkward), func(t *testing.T) {
			for _, tc := range []struct{ open, body, close string }{
				{"[", jsonLines("", []string{awkward}), "]"},
				{"{", jsonDenyMap("", []string{awkward}), "}"},
			} {
				var into any
				body := tc.open + strings.TrimSpace(tc.body) + tc.close
				if err := json.Unmarshal([]byte(body), &into); err != nil {
					t.Errorf("renders JSON nothing can parse: %v\n%s", err, body)
				}
			}
			// And the value survives rather than merely parsing.
			var got []string
			if err := json.Unmarshal([]byte("["+strings.TrimSpace(jsonLines("", []string{awkward}))+"]"), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0] != awkward {
				t.Errorf("round trip = %q, want %q", got, awkward)
			}
		})
	}
}

// What the list no longer carries, and so what a host nobody declares anything
// on can read. Asserted rather than left implicit: these were built in, the
// removal was deliberate, and a rule creeping back would otherwise be invisible
// until a fleet found itself covered twice.
var relocated = []string{
	"/home/op/.ssh/id_rsa",
	"/home/op/.ssh/id_ed25519",
	"/srv/tls/server.key",
	"/srv/tls/chain.pem",
	"/home/op/.aws/credentials",
	"/srv/app/.env",
	"/srv/app/secrets.yml",
	"/srv/group_vars/all.vault",
	"/srv/vault.yml",
	// A sops file outside this install's own store, which is ciphertext and is
	// covered where it matters by the literal store path.
	"/srv/ansible/group_vars/db.sops.yml",
	// An age identity of the operator's own. faramir mints one key, in its own
	// directory, and never learns where a second lives.
	"/home/op/age.key",
	"/home/op/.config/sops/age/keys.txt",
}

// A declared path reached through a variable, in the spellings a shell accepts.
// The read rules need a command before the path; a binding names it with none
// near it, so the binding is what refuses it.
//
// The quoted forms matter because a declared path may carry a space: "Local
// Storage" is one, and a rule that ended the value at the first space would
// never see the half that matters.
func TestADeclaredPathIsRefusedWhenBoundToAVariable(t *testing.T) {
	layout := hostlayout.Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
		{Path: "/srv/secrets.yml"},
		{Path: "/home/op/.ssh/id_rsa"},
		{Path: "/home/op/.config/chromium/Default/Local Storage"},
	}}
	rules := commandRules(layout)
	res := make([]*regexp.Regexp, 0, len(rules))
	for _, rule := range rules {
		res = append(res, regexp.MustCompile("(?i)"+rule))
	}
	matches := func(cmd string) bool {
		for _, re := range res {
			if re.MatchString(cmd) {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{
		`p=/srv/secrets.yml`,
		`p="/srv/secrets.yml"`,
		`p='/srv/secrets.yml'`,
		`export KEY="/home/op/.ssh/id_rsa"`,
		`p="/home/op/.config/chromium/Default/Local Storage"`,
		`for d in /srv; do cat /srv/secrets.yml; done`,
		// Anywhere inside the quotes, not only where the value opens: the value
		// is bounded by the quote rather than by the first space.
		`p="see /srv/secrets.yml for it"`,
	} {
		if !matches(cmd) {
			t.Errorf("%q is allowed, and it names a declared file", cmd)
		}
	}
	// A quoted value that opens with something other than a path character is
	// prose. Refusing a sentence for holding a word out of a declared path costs
	// an operator a refusal they cannot act on.
	for _, cmd := range []string{
		`echo "my secrets talk"`,
		`git commit -m "rotate the secrets"`,
		`title="my writing about ordinary things"`,
		`msg=hello secrets`,
		`title="my secrets talk"`,
		`msg='the secrets are safe'`,
	} {
		if matches(cmd) {
			t.Errorf("%q is refused, and it reaches no declared file", cmd)
		}
	}
}
