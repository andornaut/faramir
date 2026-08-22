package install

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

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

// A credential faramir neither writes nor reads is the operator's to declare,
// so nothing is compiled in and a bare install does not block it.
func TestTheRelocatedRulesAreGone(t *testing.T) {
	bare := jsFragments(Layout{})
	res := make([]*regexp.Regexp, 0, len(bare))
	for _, fragment := range bare {
		res = append(res, regexp.MustCompile(fragment))
	}
	for _, path := range relocated {
		if matchesAnyPath(res, path) {
			t.Errorf("%s is refused by a built-in rule, which was relocated", path)
		}
	}
	// And they are refusable by declaring them, which is where they went.
	declared := Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
		{Name: "id_rsa"}, {Name: "*.pem"}, {Name: ".env*"},
	}}
	for _, fragment := range jsFragments(declared) {
		res = append(res, regexp.MustCompile(fragment))
	}
	for _, path := range []string{"/home/op/.ssh/id_rsa", "/srv/tls/chain.pem", "/srv/app/.env"} {
		if !matchesAnyPath(res, path) {
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
	layout := Layout{
		ConfigDir:  "/opt/faramir",
		LogDir:     "/srv/log/faramir",
		LibexecDir: "/opt/faramir/libexec",
	}
	rules := claudeRules(layout)
	for _, want := range []string{
		"Read(/opt/faramir/**)",         // the age key, the SSH key, config.toml
		"Read(/opt/faramir/secrets/**)", // the managed sops files
		"Read(/srv/log/faramir/**)",     // the audit log
		"Read(/opt/faramir/libexec/**)", // wrap.sh and the guard
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the rules do not carry %q", want)
		}
	}
	// And not the defaults beside them: a rule naming where the file would have
	// been refuses a path on somebody else's host and leaves this one open.
	for _, unwanted := range []string{
		"Read(" + DefaultConfigDir + "/**)",
		"Read(" + DefaultLogDir + "/**)",
		"Read(" + DefaultLibexecDir + "/**)",
	} {
		if slices.Contains(rules, unwanted) {
			t.Errorf("the rules carry %q, which this layout moved", unwanted)
		}
	}
}

func matchesAnyPath(res []*regexp.Regexp, path string) bool {
	for _, re := range res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// The point of the exercise: one list, and every agent that has a rule file
// for it rendering the same paths. Each rendering is checked
// for a token from every entry, so an agent whose spelling drops one fails here
// rather than in somebody's home directory.
//
// A token rather than the whole pattern, the spellings differing by design;
// what must not differ is which paths appear at all.
func TestEveryAgentsRulesCoverEveryProtectedPath(t *testing.T) {
	layout := testLayout()
	type rendering struct{ asset, body string }
	rendered := make([]rendering, 0, 3)
	for _, asset := range []string{
		"agent/claude/settings.json",
		"agent/permissions.json.tmpl",
	} {
		body, err := render(asset, layout)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		rendered = append(rendered, rendering{asset, string(body)})
	}
	// pi's rules are in the extension it installs rather than in a config file.
	body, err := renderData("agent/pi/extension.ts.tmpl", pluginData{
		BinDir: "/usr/local/bin", Agent: "pi", Path: ".pi/extensions/faramir.ts",
		Layout: layout,
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, rendering{"agent/pi/extension.ts.tmpl", string(body)})

	if len(rendered) < 3 {
		t.Fatalf("rendered %d file(s), want the two config assets and the extension: "+
			"an agent missing here is one nothing checks", len(rendered))
	}
	for _, r := range rendered {
		// Two of these spellings are regexes, where "." arrives escaped, so the
		// backslashes come out before the search: what is being asserted is that
		// the path is in there at all, not how it had to be written.
		flat := strings.ReplaceAll(r.body, `\`, "")
		for _, dir := range installDirs(layout) {
			if !strings.Contains(flat, dir) {
				t.Errorf("%s does not refuse %s", r.asset, dir)
			}
		}
	}
}

// Read and write take the same paths. A value the agent cannot read is one it
// can still destroy, and an age key replaced is every managed file unreadable
// retroactively, so a list that covers one and not the other is half a rule.
func TestReadAndWriteAreRefusedTheSamePaths(t *testing.T) {
	body, err := render("agent/claude/settings.json", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	reads, edits := map[string]bool{}, map[string]bool{}
	for _, m := range regexp.MustCompile(`"(Read|Edit)\((.*?)\)"`).FindAllStringSubmatch(string(body), -1) {
		if m[1] == "Read" {
			reads[m[2]] = true
		} else {
			edits[m[2]] = true
		}
	}
	if len(reads) == 0 {
		t.Fatal("no Read rules were rendered")
	}
	for pattern := range reads {
		if !edits[pattern] {
			t.Errorf("%s is refused on read and permitted on edit", pattern)
		}
	}
	for pattern := range edits {
		if !reads[pattern] {
			t.Errorf("%s is refused on edit and permitted on read", pattern)
		}
	}
}

// The two plugin hosts install the same rules, and what makes that true is that
// they name one asset rather than two files kept in step by hand. Asserted
// against the targets: rendering both and comparing would compare one file with
// itself and pass however the targets were wired.
func TestBothPluginHostsGetTheSameRules(t *testing.T) {
	assets := map[string][]string{}
	for _, name := range []string{"opencode", "kilocode"} {
		for _, file := range agentTargets[name].accountFiles {
			assets[name] = append(assets[name], file.asset)
		}
	}
	if len(assets["opencode"]) == 0 {
		t.Fatal("opencode writes no account-wide rules")
	}
	if !slices.Equal(assets["opencode"], assets["kilocode"]) {
		t.Errorf("opencode writes %v and Kilo Code writes %v, so the two lists can "+
			"drift", assets["opencode"], assets["kilocode"])
	}
}

// An empty directory in the list is a rule that refuses every absolute path.
// Layout is built field by field and a caller filling only what it needs is the
// ordinary way to reach one, so the partial layouts below are the cases.
func TestInstallDirsAreNeverEmpty(t *testing.T) {
	for _, layout := range []Layout{
		{},
		{ConfigDir: "/opt/conf"},
		{LogDir: "/var/log/x"},
		testLayout(),
	} {
		dirs := installDirs(layout)
		if len(dirs) == 0 {
			t.Errorf("installDirs(%+v) yielded nothing, so every rule built from it "+
				"covers no path and the tests over it assert nothing", layout)
		}
		for _, dir := range dirs {
			if strings.TrimSpace(dir) == "" || dir == "/" {
				t.Errorf("installDirs(%+v) yielded %q, which refuses everything", layout, dir)
			}
		}
	}
}

// Enrolling a tree writes the deny rules into it, not only the hook. A tree can
// be enrolled on a host where `faramir init --agent` never ran, and the
// enrolment is what the operator did: without this the agent's file tools are
// refused nothing in the one project faramir was pointed at.
func TestEnrollingATreeWritesTheDenyRules(t *testing.T) {
	for _, tc := range []struct {
		agent string
		file  string
		want  string
	}{
		{"claude", ".claude/settings.local.json", `"Read(/etc/faramir/**)"`},
		{"opencode", "opencode.json", `"/etc/faramir/*": "deny"`},
		{"kilocode", "kilo.json", `"/etc/faramir/*": "deny"`},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			target := agentTargets[tc.agent]
			var file agentFile
			for _, candidate := range target.files {
				if candidate.path == tc.file {
					file = candidate
				}
			}
			if file.path == "" {
				t.Fatalf("%s writes no %s", tc.agent, tc.file)
			}
			body, err := assetFor(target, file, "/etc/faramir")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), tc.want) {
				t.Errorf("%s carries no deny rule for this install's own directory:\n%s",
					tc.file, body)
			}
			// This install's own directories with them, which are literal rather
			// than patterns: a store moved by --config-dir is the one refused.
			if !strings.Contains(string(body), "/etc/faramir/secrets") {
				t.Errorf("%s does not refuse this install's secrets directory:\n%s",
					tc.file, body)
			}
		})
	}
}

// The rules an enrolment writes are the rules doctor re-renders to compare
// against. Both go through ruleLayout, so a tree that was just enrolled is not
// reported as drifted.
func TestWhatAnEnrolmentWritesIsWhatDoctorCompares(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "project")
	if err := os.MkdirAll(filepath.Join(tree, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := agentTargets["claude"]
	file := target.files[0]
	body, err := assetFor(target, file, "/etc/faramir")
	if err != nil {
		t.Fatal(err)
	}
	// Through the merge, as writeAgentFiles writes it: the first write is
	// byte-for-byte what a second would produce, and the asset as authored is
	// not.
	merged, err := mergeJSON(nil, body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tree, file.path)
	if err := os.WriteFile(path, merged, 0o640); err != nil {
		t.Fatal(err)
	}
	carries, err := carriesWhatWeWrite(target, file, path, "/etc/faramir")
	if err != nil {
		t.Fatal(err)
	}
	if !carries {
		t.Error("a file written by an enrolment reads as drifted to the check that " +
			"compares it, so doctor would report every enrolled tree")
	}
}
