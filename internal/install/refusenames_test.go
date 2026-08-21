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
			rule := refusedNameRule(tc.name)
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
		Refused:   []config.RefusedPath{{Name: "*.htpasswd"}, {Name: ".storage/"}},
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
	layout := Layout{ConfigDir: "/etc/faramir", Refused: []config.RefusedPath{{Name: pattern}}}
	if rule := refusedNameRule(pattern); rule.kind != kindName {
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
	path := config.RefusedPath{Path: "/etc/luks/volume.key"}
	name := config.RefusedPath{Name: "volume.key"}
	if sameRefusal(path, name) {
		t.Error("a path and a name were read as one entry")
	}
	entries, added := refusedWith([]config.RefusedPath{path}, name)
	if !added || len(entries) != 2 {
		t.Errorf("adding a name beside a path gave %d entry(ies), added=%v", len(entries), added)
	}
	if _, again := refusedWith(entries, name); again {
		t.Error("the same name was added twice")
	}
}

// What a pattern matches is printed where it is written, that being the moment
// the operator can still narrow it. A wide one is otherwise silent.
func TestAPatternSaysWhatItMatches(t *testing.T) {
	for name, want := range map[string]string{
		"*.sops.yml":   `ends in ".sops.yml"`,
		".env*":        `starts with ".env"`,
		"secrets*.yml": `matches "secrets*.yml"`,
		".storage/":    `under any directory named ".storage"`,
		"auth":         `named "auth"`,
	} {
		if got := RefusedNameMatches(name); !strings.Contains(got, want) {
			t.Errorf("%s: %q does not say %q", name, got, want)
		}
	}
}

// Removing a built-in fails rather than reporting that nothing was refused. The
// rule is faramir's own, so the request cannot be met and the host goes on
// refusing what was named; saying "not refused, nothing removed" would answer a
// request to stop refusing something with a sentence denying it was refused at
// all, which the operator would meet again as an agent still being denied.
func TestRemovingABuiltInRuleFails(t *testing.T) {
	dir := writeRefuseConfig(t, "")
	before, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"*.sops.yml", "age.key", "sops/age/", ".config/faramir/"} {
		_, removed, rmErr := RemoveRefusedPath(Options{ConfigDir: dir},
			config.RefusedPath{Name: name})
		if rmErr == nil {
			t.Errorf("%s: removing a built-in was accepted", name)
			continue
		}
		for _, want := range []string{"compiled into faramir", "refuse ls"} {
			if !strings.Contains(rmErr.Error(), want) {
				t.Errorf("%s: error %q does not say %q", name, rmErr, want)
			}
		}
		if removed.Refuses() != "" {
			t.Errorf("%s: reported %q as removed", name, removed.Refuses())
		}
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused removal rewrote the config:\n%s", after)
	}
}

// The pattern is compared as the rule it becomes, not as the string typed:
// "*.sops.yml" is the built-in suffix written another way, while ".sops.yml" is a
// file of that name and is nobody's rule yet.
func TestABuiltInIsFoundByTheRuleNotTheSpelling(t *testing.T) {
	if _, ok := BuiltInRefusalFor("*.sops.yml"); !ok {
		t.Error(`"*.sops.yml" did not find the built-in suffix`)
	}
	if _, ok := BuiltInRefusalFor(".sops.yml"); ok {
		t.Error(`".sops.yml" as a file name found the suffix rule, which is a different rule`)
	}
	// One that used to be built in and is now the operator's to declare.
	if _, ok := BuiltInRefusalFor("*.pem"); ok {
		t.Error(`"*.pem" was read as a built-in after it was relocated`)
	}
	if _, ok := BuiltInRefusalFor("*.htpasswd"); ok {
		t.Error("a pattern faramir does not carry was read as a built-in")
	}
}

// The same answer for the operator who names the file rather than the pattern.
// "Stop refusing ~/.config/sops/age/keys.txt" and "stop refusing the sops/age/
// request, and only one of them names a pattern.
func TestRemovingAPathABuiltInCoversFails(t *testing.T) {
	dir := writeRefuseConfig(t, "")
	var err error
	for _, path := range []string{
		"/home/op/age.key",                   // an exact name
		"/etc/faramir/secrets/db.sops.yml",   // a suffix
		"/home/op/.config/sops/age/keys.txt", // a directory
	} {
		_, removed, rmErr := RemoveRefusedPath(Options{ConfigDir: dir},
			config.RefusedPath{Path: path})
		if rmErr == nil {
			t.Errorf("%s: removing a path a built-in covers was accepted", path)
			continue
		}
		if !strings.Contains(rmErr.Error(), "compiled into faramir") {
			t.Errorf("%s: error %q does not say where the rule comes from", path, rmErr)
		}
		if removed.Refuses() != "" {
			t.Errorf("%s: reported %q as removed", path, removed.Refuses())
		}
	}
	// A path no built-in covers is not refused here, an rm of what is not
	// declared being a request for the state the host is already in. It goes on
	// to the steps, which want root, so what is asserted is that it got past this
	// check rather than that the run succeeded.
	_, _, err = RemoveRefusedPath(Options{ConfigDir: dir},
		config.RefusedPath{Path: "/mnt/vol/luks.key"})
	if err != nil && strings.Contains(err.Error(), "compiled into faramir") {
		t.Errorf("a path no built-in covers was refused as one: %v", err)
	}
}

// What each built-in matches, since the message above names a rule and the
// wrong one would send the operator to the wrong place.
func TestABuiltInKnowsWhatItCovers(t *testing.T) {
	for path, want := range map[string]string{
		"/home/op/age.key":                   "age.key",
		"/home/op/.config/sops/age/keys.txt": "sops/age/",
		"/home/op/.config/faramir/x":         ".config/faramir/",
		"/etc/faramir/x.sops.yml":            ".sops.yml",
	} {
		rule, ok := BuiltInRefusalCovering(path)
		if !ok {
			t.Errorf("%s: no built-in was found to cover it", path)
			continue
		}
		if rule.Entry != want {
			t.Errorf("%s: covered by %q, want %q", path, rule.Entry, want)
		}
	}
	// An ordinary file, and one a relocated rule used to cover.
	for _, path := range []string{"/srv/app/config.yml", "/home/op/.ssh/id_rsa"} {
		if rule, ok := BuiltInRefusalCovering(path); ok {
			t.Errorf("%s was read as covered by the built-in %q", path, rule.Entry)
		}
	}
}

// An install may declare what faramir already refuses, and taking that entry
// back is a request it can meet: the entry is this install's, and what remains
// is the built-in. The command asks before it has root and so before it has
// read anything, which is where the declared half has to be read too.
func TestADeclaredEntryIsRemovableWhateverElseCoversIt(t *testing.T) {
	// A path a built-in covers by suffix, which is the case the e2e suite meets:
	// a key on a volume nobody has mounted is refused by the entry that named it
	// and by the built-in ".key" alike.
	dir := writeRefuseConfig(t, "[[secret.refuse]]\npath = \"/etc/faramir/secrets/a.sops.yml\"\n"+
		"[[secret.refuse]]\nname = \"*.sops.yml\"\n")

	for _, asked := range []config.RefusedPath{
		{Path: "/etc/faramir/secrets/a.sops.yml"},
		{Name: "*.sops.yml"},
	} {
		if err := BuiltInRefusalError(dir, asked); err != nil {
			t.Errorf("%s: a declared entry was refused: %v", asked.Refuses(), err)
		}
	}
	// One nothing declares is still refused, which is the whole of the check.
	if err := BuiltInRefusalError(dir, config.RefusedPath{Name: "age.key"}); err == nil {
		t.Error("a built-in nothing declares was not refused")
	}
	// A host with no config declares none, so there is no entry to take back and
	// the built-in is the whole of the answer.
	if err := BuiltInRefusalError(t.TempDir(), config.RefusedPath{Name: "age.key"}); err == nil {
		t.Error("a built-in was removable on a host that declares nothing")
	}
}
