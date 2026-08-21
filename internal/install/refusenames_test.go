package install

import (
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
		"*.pem":        `ends in ".pem"`,
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
