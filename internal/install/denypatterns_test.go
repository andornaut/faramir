package install

import (
	"regexp"
	"strings"
	"testing"
)

// renderDenyPatterns is the file as an install would write it.
func renderDenyPatterns(t *testing.T, layout Layout) string {
	t.Helper()
	body, err := render("agent/hooks/deny-patterns.txt", layout)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// denyRules is the rendered file's rules, comments and blanks dropped, the way
// the guard reads it.
func denyRules(text string) []string {
	var out []string
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// --ssh-key may put the broker's identity anywhere. Inside the config
// directory the rules already cover it by path; outside, the id_* class is all
// that is left, and a key named for the host it opens matches none of it. The
// key's own path is named, so where it is put makes no difference.
func TestTheDenyRulesNameTheConfiguredSSHKey(t *testing.T) {
	opts := Options{
		AgentUser: "operator", ConfigDir: "/etc/faramir",
		SSHKey: "/srv/keys/broker_ed25519",
	}
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		t.Fatal(err)
	}
	rules := denyRules(renderDenyPatterns(t, layout))

	for _, cmd := range []string{
		"cat /srv/keys/broker_ed25519",
		"base64 /srv/keys/broker_ed25519",
		"cp /srv/keys/broker_ed25519 /tmp/x",
	} {
		if !matchesAny(t, rules, cmd) {
			t.Errorf("a key --ssh-key put outside the config directory is not "+
				"refused: %q", cmd)
		}
	}
}

// The path is interpolated into an alternation, so an empty one leaves a branch
// that matches the empty string, and the rule then refuses every command the
// tool list names. Layout.SSHKey is never empty from an install, but the
// template is rendered elsewhere too, and the failure is silent and total.
func TestAnUnsetSSHKeyDoesNotEmptyAnAlternation(t *testing.T) {
	rules := denyRules(renderDenyPatterns(t, Layout{
		ConfigDir: "/etc/faramir", BinDir: "/usr/local/bin",
		LibexecDir: "/usr/local/libexec/faramir", LogDir: "/var/log/faramir",
	}))
	if len(rules) == 0 {
		t.Fatal("no rules rendered")
	}
	for _, rule := range rules {
		for _, empty := range []string{"(|", "||", "|)"} {
			if strings.Contains(rule, empty) {
				t.Errorf("an empty alternation branch (%q) makes this rule match "+
					"everything: %s", empty, rule)
			}
		}
	}
	// The consequence, stated as behaviour rather than as syntax.
	for _, harmless := range []string{"ls", "cat README.md", "go test ./..."} {
		if matchesAny(t, rules, harmless) {
			t.Errorf("an ordinary command is refused with no --ssh-key rendered: %q",
				harmless)
		}
	}
}

// matchesAny compiles the rules the way the guard does and reports whether any
// of them refuses the command.
func matchesAny(t *testing.T, rules []string, cmd string) bool {
	t.Helper()
	for _, rule := range rules {
		re, err := regexp.Compile("(?i)" + rule)
		if err != nil {
			t.Fatalf("rule does not compile: %s: %v", rule, err)
		}
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}
