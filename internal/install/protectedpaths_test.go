package install

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// samples is a path per entry in protectedPaths that the entry must refuse, and
// one nearby that it must not.  Written by hand rather than derived from the
// entry, so a rendering and its test cannot be wrong in the same direction: a
// generator bug that widens a pattern is caught by the second column, and one
// that empties it by the first.
var samples = []struct {
	refused string
	allowed string
}{
	{"/srv/app/secrets.yml", "/srv/app/settings.yml"},
	{"/srv/app/secrets-prod.yaml", "/srv/app/settings.yaml"},
	{"/etc/faramir/secrets/db.sops.yml", "/srv/app/db.yml"},
	{"/srv/vars.sops.yaml", "/srv/vars.yaml"},
	{"/srv/vars.sops.json", "/srv/vars.json"},
	{"/srv/group_vars/all.vault", "/srv/group_vars/all.yml"},
	{"/srv/vault.yml", "/srv/revault.yml"},
	{"/home/op/age.key", "/home/op/age.pub"},
	{"/home/op/.config/sops/age/keys.txt", "/home/op/notes.txt"},
	{"/home/op/.ssh/id_ed25519", "/home/op/.ssh/id_ed25519.pub"},
	{"/home/op/.ssh/id_rsa", "/home/op/.ssh/authorized_keys"},
	{"/srv/tls/server.key", "/srv/tls/server.crt"},
	{"/srv/tls/chain.pem", "/srv/tls/chain.txt"},
	{"/home/op/.aws/credentials", "/home/op/.aws/config"},
	// The one distinction the list makes on purpose: a dotenv is refused and
	// faramir.env, which holds faramir:// refs, is meant to be read.
	{"/srv/app/.env", "/srv/app/faramir.env"},
	{"/srv/app/.env.production", "/srv/app/env.example"},
	{"/home/op/.config/faramir/config.toml", "/home/op/.config/other/config.toml"},
}

// The Go list is what every rendering is derived from, so it is what the
// samples are checked against first: an entry nothing matches is a path the
// list only appears to cover.
func TestEveryProtectedPathHasASampleThatReachesIt(t *testing.T) {
	// Each refused sample must be matched by the JavaScript spelling, that being
	// the one form these tests can execute directly.
	res := make([]*regexp.Regexp, 0, len(protectedPaths))
	for _, fragment := range jsFragments() {
		re, err := regexp.Compile(fragment)
		if err != nil {
			t.Fatalf("fragment %q does not compile: %v", fragment, err)
		}
		res = append(res, re)
	}
	for _, s := range samples {
		if !matchesAnyPath(res, s.refused) {
			t.Errorf("%s is refused by no pattern", s.refused)
		}
		if matchesAnyPath(res, s.allowed) {
			t.Errorf("%s is refused, and should not be", s.allowed)
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
// for it rendering the same paths.  Each rendering is checked
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
		Dirs: installDirs(layout),
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, rendering{"agent/pi/extension.ts.tmpl", string(body)})

	for _, r := range rendered {
		// Two of these spellings are regexes, where "." arrives escaped, so the
		// backslashes come out before the search: what is being asserted is that
		// the path is in there at all, not how it had to be written.
		flat := strings.ReplaceAll(r.body, `\`, "")
		for _, p := range protectedPaths {
			// The literal part of the entry, which every spelling keeps: the
			// wildcard and the anchoring are what they are free to differ about.
			token := strings.TrimSuffix(strings.SplitN(p.value, "*", 2)[0], "/")
			if !strings.Contains(flat, token) {
				t.Errorf("%s covers no path matching %q (%s)", r.asset, p.value, p.why)
			}
		}
		for _, dir := range installDirs(layout) {
			if !strings.Contains(flat, dir) {
				t.Errorf("%s does not refuse %s", r.asset, dir)
			}
		}
	}
}

// Read and write take the same paths.  A value the agent cannot read is one it
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
// they name one asset rather than two files kept in step by hand.  Asserted
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
		for _, dir := range installDirs(layout) {
			if strings.TrimSpace(dir) == "" || dir == "/" {
				t.Errorf("installDirs(%+v) yielded %q, which refuses everything", layout, dir)
			}
		}
	}
}
