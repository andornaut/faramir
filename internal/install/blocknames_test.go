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

// The shapes a declared name may take, and the kind each is read as. The
// classification is what decides how wide the rendered rule is, so it is
// asserted per shape rather than through one example.
func TestADeclaredNameIsReadAsItsShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  pathKind
		value string
	}{
		{"auth", kindName, "auth"},
		{".storage/auth", kindName, ".storage/auth"},
		{"*.htpasswd", kindSuffix, ".htpasswd"},
		{".env*", kindPrefix, ".env"},
		{"secrets*.yml", kindGlobName, "secrets*.yml"},
		{".storage/", kindDir, ".storage/"},
		{"ssl/key/", kindDir, "ssl/key/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := blockedNameRule(tc.name)
			if rule.kind != tc.kind {
				t.Errorf("kind %v, want %v", rule.kind, tc.kind)
			}
			if rule.value != tc.value {
				t.Errorf("value %q, want %q", rule.value, tc.value)
			}
		})
	}
}

// A name entry has to reach every agent's rules, or it is refused in the
// spelling of whichever one was tested and nowhere else. The container case is
// the one it exists for: the agent names /config/..., which no rule carrying a
// host path can match.
func TestADeclaredNameReachesEveryAgentSpelling(t *testing.T) {
	layout := Layout{
		ConfigDir: "/etc/faramir",
		Blocked:   []config.BlockedPath{{Name: "*.htpasswd"}, {Name: ".storage/"}},
	}
	rules := claudeRules(layout)
	for _, want := range []string{"Read(**/*.htpasswd)", "Edit(**/*.htpasswd)",
		"Read(**/.storage/**)"} {
		if !slices.Contains(rules, want) {
			t.Errorf("Claude Code's rules do not carry %q", want)
		}
	}
	plugin := pluginPatterns(layout)
	if !slices.Contains(plugin, "*.htpasswd") {
		t.Errorf("the plugin hosts' patterns do not carry the suffix: %v", plugin)
	}
	var carried bool
	for _, fragment := range jsFragments(layout) {
		if strings.Contains(fragment, "htpasswd") {
			carried = true
		}
	}
	if !carried {
		t.Error("pi's fragments do not carry the suffix")
	}
}

// A name may carry a directory component, which is the narrow form of the
// container case: a file inside a directory of a given name, without refusing
// every file of that name and without sweeping in the whole directory.
func TestANameMayNameAFileInsideADirectory(t *testing.T) {
	const pattern = ".storage/core.config_entries"
	layout := Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{{Name: pattern}}}
	if rule := blockedNameRule(pattern); rule.kind != kindName {
		t.Errorf("kind %v, want a name", rule.kind)
	}
	if !slices.Contains(claudeRules(layout), "Read(**/"+pattern+")") {
		t.Error("Claude Code's rules do not carry the pattern")
	}
	if !slices.Contains(pluginPatterns(layout), "*"+pattern) {
		t.Error("the plugin hosts' patterns do not carry it")
	}
	// pi applies its own regex, so this is the one spelling a test can execute.
	var matched, swept bool
	for _, fragment := range jsFragments(layout) {
		if !strings.Contains(fragment, "storage") {
			continue
		}
		re := regexp.MustCompile(fragment)
		matched = matched || re.MatchString("/config/.storage/core.config_entries")
		swept = swept || re.MatchString("/config/.storage/auth")
	}
	if !matched {
		t.Error("the container path is not refused")
	}
	if swept {
		t.Error("a sibling in the same directory is refused, so the rule is wider than it names")
	}
}

// The two forms are separate entries even where they read alike: they render
// different rules, so one must not stand in for the other on add or on rm.
func TestAPathAndANameAreNotOneEntry(t *testing.T) {
	path := config.BlockedPath{Path: "/etc/luks/volume.key"}
	name := config.BlockedPath{Name: "volume.key"}
	if sameBlock(path, name) {
		t.Error("a path and a name were read as one entry")
	}
	entries, added := blockedWith([]config.BlockedPath{path}, name)
	if !added || len(entries) != 2 {
		t.Errorf("adding a name beside a path gave %d entry(ies), added=%v", len(entries), added)
	}
	if _, again := blockedWith(entries, name); again {
		t.Error("the same name was added twice")
	}
}

// What a pattern matches is printed where it is written, that being the moment
// the operator can still narrow it. A wide one is otherwise silent.
func TestAPatternSaysWhatItMatches(t *testing.T) {
	for name, want := range map[string]string{
		"*.htpasswd":   `ends in ".htpasswd"`,
		".env*":        `starts with ".env"`,
		"secrets*.yml": `matches "secrets*.yml"`,
		".storage/":    `under any directory named ".storage"`,
		"auth":         `named "auth"`,
	} {
		if got := BlockedNameMatches(name); !strings.Contains(got, want) {
			t.Errorf("%s: %q does not say %q", name, got, want)
		}
	}
}

// Nothing is compiled in, so a name or a path outside this install's own
// directories is removable whatever it is: a check that refused one of these
// would be refusing on grounds that no longer exist.
func TestOnlyTheLayoutBlocksWithoutAnEntry(t *testing.T) {
	dir := writeBlockConfig(t, "")
	for _, asked := range []config.BlockedPath{
		{Name: "age.key"}, {Name: "*.pem"}, {Name: "id_rsa"},
		{Path: "/home/op/.config/sops/age/keys.txt"},
		{Path: "/home/op/.ssh/id_rsa"},
	} {
		if err := BuiltInRuleError(dir, asked); err != nil {
			t.Errorf("%s: removal was refused with nothing to refuse it: %v",
				asked.Blocks(), err)
		}
	}
}

// The install's own directories are the rules an entry cannot take back: they
// come out of the layout on every render. Reporting "nothing removed" for one
// would read as the file becoming readable.
func TestRemovingAPathTheLayoutBlocksIsRefused(t *testing.T) {
	dir := writeBlockConfig(t, "")
	for _, asked := range []config.BlockedPath{
		{Path: dir},
		{Path: filepath.Join(dir, "age.key")},
		{Path: filepath.Join(dir, "secrets", "db.sops.yml")},
		{Path: "/var/log/faramir/audit.log"},
	} {
		err := BuiltInRuleError(dir, asked)
		if err == nil {
			t.Errorf("%s: removing a path the layout blocks was allowed, which "+
				"reports it as no longer blocked", asked.Blocks())
			continue
		}
		if !strings.Contains(err.Error(), "block ls") {
			t.Errorf("%s: the refusal does not say where to look: %v", asked.Blocks(), err)
		}
	}
}

// A neighbour whose name merely starts the same way is not under it.
func TestASiblingOfAnInstalledDirectoryIsRemovable(t *testing.T) {
	dir := writeBlockConfig(t, "")
	if err := BuiltInRuleError(dir, config.BlockedPath{Path: dir + "-notes"}); err != nil {
		t.Errorf("%s-notes was read as being under %s: %v", dir, dir, err)
	}
}

// A declared entry is removable, which is what the check above must not get in
// the way of.
func TestADeclaredEntryIsRemovable(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\npath = \"/home/op/age.key\"\n"+
		"[[secret.block]]\nname = \"age.key\"\n")
	for _, asked := range []config.BlockedPath{
		{Path: "/home/op/age.key"}, {Name: "age.key"},
	} {
		if err := BuiltInRuleError(dir, asked); err != nil {
			t.Errorf("%s: a declared entry was refused: %v", asked.Blocks(), err)
		}
	}
}

// A dozen names in one command, which is what a first run pastes and what a
// converge hands over. What the fold has to get right is which entries were new
// and what the resulting set is; that it costs one write rather than a dozen is
// the caller applying it once, which the e2e suite exercises on a real host.
func TestSeveralEntriesFoldIntoOneSet(t *testing.T) {
	existing := []config.BlockedPath{{Name: "*.pem"}}
	asked := []config.BlockedPath{
		{Name: "id_rsa"},
		{Name: "*.pem"}, // already there
		{Name: ".env*"},
		{Path: "/mnt/vol/luks.key"},
		{Name: "id_rsa"}, // named twice in one call
	}
	entries, added := foldBlocked(existing, asked)
	if want := []bool{true, false, true, true, false}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v: an entry already there, and one named twice "+
			"in one call, are both reported as not added", added, want)
	}
	// Order kept, and the entry already there is not moved by the ones added
	// beside it.
	want := []string{"*.pem", "id_rsa", ".env*", "/mnt/vol/luks.key"}
	if len(entries) != len(want) {
		t.Fatalf("the set holds %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for i, refuses := range want {
		if got := entries[i].Blocks(); got != refuses {
			t.Errorf("entry %d is %q, want %q", i, got, refuses)
		}
	}
	// The one it started with is untouched by a fold that added nothing.
	if _, added := foldBlocked(entries, []config.BlockedPath{{Name: "*.pem"}}); added[0] {
		t.Error("an entry already in the set was reported as added")
	}
}

// One bad entry writes none of the list. A partial write would leave the
// operator to work out which half of what they pasted took.
func TestOneBadEntryWritesNoneOfTheList(t *testing.T) {
	dir := writeBlockConfig(t, "")
	before, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = AddBlockedPaths(Options{ConfigDir: dir}, []config.BlockedPath{
		{Name: "id_rsa"},
		{Name: "*"}, // every file on the host
		{Name: ".env*"},
	})
	if err == nil {
		t.Fatal("a list carrying a pattern that matches everything was accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused list wrote part of itself:\n%s", after)
	}
}

// A declared name reached through a variable, in the spellings a shell accepts.
// The read rules need a command before the path; a binding names it with none
// near it, so the binding is what refuses it.
//
// The quoted forms matter here rather than for the install's own directories:
// "Local Storage" is a declared name with a space in it, and a rule that ended
// the value at the first space would never see the half that matters.
func TestADeclaredNameIsRefusedWhenBoundToAVariable(t *testing.T) {
	layout := Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
		{Name: "secrets*"}, {Name: "id_rsa"}, {Name: "Local Storage/"},
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
		`p="/my dir/secrets.yml"`,
		`export KEY="$HOME/.ssh/id_rsa"`,
		`p='~/.ssh/id_rsa'`,
		`p="./secrets.yml"`,
		`p="$HOME/.config/chromium/Default/Local Storage"`,
		`for d in /srv; do cat $d/secrets.yml; done`,
		// The directory this repo's own package is named for, which is what
		// found the rule: a loop over it reaches every file inside.
		`d=internal/secretstore`,
		// Anywhere inside the quotes, not only where the value opens: the value
		// is bounded by the quote rather than by the first space.
		`p="see /srv/secrets.yml for it"`,
		// "secrets*" is an open-ended prefix, so it takes every name that starts
		// with those seven characters and not only the ones that continue with a
		// dot. Held here because it is the whole of what the entry means.
		`p=/srv/secretsx.yml`,
		`p=/srv/secretstore/notes.md`,
	} {
		if !matches(cmd) {
			t.Errorf("%q is allowed, and it names a declared file", cmd)
		}
	}
	// A quoted value that opens with something other than a path character is
	// prose. A blocked name is often an ordinary word, and refusing a sentence
	// for containing one costs an operator a refusal they cannot act on.
	for _, cmd := range []string{
		`echo "my secrets talk"`,
		`git commit -m "rotate the secrets"`,
		`title="my writing about ordinary things"`,
		// An assignment whose value is a word, followed by a blocked name that
		// is an ordinary word too. The binding rule takes the subjects with the
		// whitespace dropped from what may precede a name, or the value would
		// reach past its own word into this one.
		`msg=hello secrets`,
		`title="my secrets talk"`,
		`msg='the secrets are safe'`,
	} {
		if matches(cmd) {
			t.Errorf("%q is refused, and it reaches no declared file", cmd)
		}
	}
}
