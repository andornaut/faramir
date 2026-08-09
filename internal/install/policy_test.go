package install

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// rulePatterns pulls every argsPattern out of the rendered policy file, keyed by
// tool.  Parsed rather than compared as text: a rule that does not compile is
// one Gemini drops.
func rulePatterns(t *testing.T) map[string][]*regexp.Regexp {
	t.Helper()
	body, err := render("agent/gemini/policies.toml.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]*regexp.Regexp{}
	var tool string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "toolName"):
			tool = strings.Trim(strings.SplitN(line, "=", 2)[1], ` "`)
		case strings.HasPrefix(line, "argsPattern"):
			raw := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			pattern := strings.Trim(raw, "'")
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("%s: pattern does not compile: %v\n%s", tool, err, pattern)
			}
			out[tool] = append(out[tool], compiled)
		}
	}
	if len(out) == 0 {
		t.Fatal("no rules were rendered")
	}
	return out
}

// matches reports whether any rule for the tool fires, serialised the way Gemini
// serialises before matching.
func matches(t *testing.T, rules map[string][]*regexp.Regexp, tool string, args map[string]any) bool {
	t.Helper()
	body, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules[tool] {
		if rule.Match(body) {
			return true
		}
	}
	return false
}

// The paths worth refusing, and the ones that must still open: a rule that
// refuses everything gets turned off.
func TestGeminiPolicyRefusesKeyMaterial(t *testing.T) {
	rules := rulePatterns(t)
	for _, tool := range []string{"read_file", "write_file", "replace"} {
		t.Run(tool, func(t *testing.T) {
			for _, path := range []string{
				"/home/op/.config/sops/age/keys.txt",
				"/home/op/.faramir/age.key",
				"/home/op/.faramir/secrets/x.sops.yml",
				"/srv/app/secrets.yml",
				"/srv/app/group_vars/vault.yml",
				"/home/op/.ssh/id_ed25519",
				"/srv/app/.env",
				"/etc/ssl/private/site.pem",
				"/home/op/creds/credentials",
				// This install's own directories, which testLayout moves off
				// their defaults.
				"/opt/conf/config.toml",
				"/opt/conf/store/x.sops.yml",
			} {
				if !matches(t, rules, tool, map[string]any{"file_path": path}) {
					t.Errorf("%s is not refused", path)
				}
			}
			for _, path := range []string{
				"/srv/app/main.go",
				"/srv/app/README.md",
				// Refs, never values, and meant to be read.
				"/srv/app/faramir.env",
				"/srv/app/docs/keychain.md",
			} {
				if matches(t, rules, tool, map[string]any{"file_path": path}) {
					t.Errorf("%s is refused and should not be", path)
				}
			}
		})
	}
}

// read_many_files takes globs, so a deny covering only read_file would leave
// the tool that reads a directory at once.
func TestGeminiPolicyCoversReadManyFiles(t *testing.T) {
	rules := rulePatterns(t)
	if len(rules["read_many_files"]) == 0 {
		t.Fatal("read_many_files has no rule")
	}
	if !matches(t, rules, "read_many_files",
		map[string]any{"include": []string{"**/*.key"}}) {
		t.Error("a glob for key material is not refused")
	}
	if matches(t, rules, "read_many_files",
		map[string]any{"include": []string{"**/*.go"}}) {
		t.Error("an ordinary glob is refused")
	}
}

// Every rule denies, and at a priority an allow written later cannot outrank.
func TestGeminiPolicyRulesDeny(t *testing.T) {
	body, err := render("agent/gemini/policies.toml.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	rules := strings.Count(text, "[[rule]]")
	if got := strings.Count(text, `decision = "deny"`); got != rules {
		t.Errorf("%d of %d rules deny", got, rules)
	}
	if got := strings.Count(text, "priority = 1000"); got != rules {
		t.Errorf("%d of %d rules carry the priority", got, rules)
	}
}
