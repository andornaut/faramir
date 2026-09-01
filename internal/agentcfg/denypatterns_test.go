package agentcfg

import (
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// renderDenyPatterns is the file as an install would write it.
func renderDenyPatterns(t *testing.T, layout hostlayout.Layout) string {
	t.Helper()
	body, err := Render("agent/hooks/deny-patterns.txt", layout)
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
	layout := testLayout()
	layout.ConfigDir = hostlayout.DefaultConfigDir
	layout.SSHKey = "/srv/keys/broker_ed25519"
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
	rules := denyRules(renderDenyPatterns(t, hostlayout.Layout{
		ConfigDir: "/etc/faramir", BinDir: "/usr/local/bin",
		LibexecDir: "/usr/local/libexec/faramir", LogDir: "/var/log/faramir",
	}))
	if len(rules) == 0 {
		t.Fatal("no rules rendered")
	}
	for _, rule := range rules {
		for _, empty := range []string{"(|", "||", "|)"} {
			if strings.Contains(withoutClasses(rule), empty) {
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

// Every rendered rule carries its kind, and the file holds them in
// denyrules.Kinds() order. First match wins on both tiers, so a rule rendered
// out of that order answers a command the broker, which sorts by the same list,
// answers differently.
//
// Rendered with an --ssh-key, which is the one rule the template writes from a
// field rather than from the catalogue: with none set the line is absent, and
// the ordering it can break goes untested.
func TestTheRenderedRulesAreInKindOrder(t *testing.T) {
	layout := testLayout()
	layout.ConfigDir = hostlayout.DefaultConfigDir
	layout.SSHKey = "/srv/keys/broker_ed25519"
	rules := denyRules(renderDenyPatterns(t, layout))
	if len(rules) == 0 {
		t.Fatal("no rules rendered")
	}

	rank := make(map[string]int, len(denyrules.Kinds()))
	for i, kind := range denyrules.Kinds() {
		rank[denyrules.KindMarker(kind)] = i
	}
	highest, highestRule := -1, ""
	for _, rule := range rules {
		for marker, at := range rank {
			if !strings.HasPrefix(rule, marker) {
				continue
			}
			if at < highest {
				t.Errorf("this rule is rendered after one of a later kind, so a "+
					"command matching both is answered by the wrong one:\n  "+
					"earlier: %s\n  this:    %s", highestRule, rule)
			}
			if at > highest {
				highest, highestRule = at, rule
			}
			break
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

// withoutClasses stands a single character in for each [...] span, where a | or
// a ) is a literal character rather than alternation syntax. A placeholder
// rather than nothing: a class is a branch, and deleting it would report the
// empty branch it left behind.
func withoutClasses(rule string) string {
	var out strings.Builder
	depth := 0
	for i := 0; i < len(rule); i++ {
		switch {
		case rule[i] == '\\' && i+1 < len(rule):
			if depth == 0 {
				out.WriteString(rule[i : i+2])
			}
			i++
		case rule[i] == '[':
			if depth == 0 {
				out.WriteByte('x')
			}
			depth++
		case rule[i] == ']' && depth > 0:
			depth--
		case depth == 0:
			out.WriteByte(rule[i])
		}
	}
	return out.String()
}

// A rule about a directory is about that directory. The subjects are
// interpolated into a command-line matcher, so an unbounded one makes the rule
// for /etc/faramir also cover /etc/faramir-notes.md: an agent is refused a file
// nobody blocked, and the refusal names a rule that has nothing to do with it.
func TestACommandRuleDoesNotReachASiblingPath(t *testing.T) {
	layout := hostlayout.Layout{
		ConfigDir: "/etc/faramir", BinDir: "/usr/local/bin",
		LibexecDir: "/usr/local/libexec/faramir", LogDir: "/var/log/faramir",
		Blocked: []config.BlockedPath{{Path: "/srv/luks.key"}},
	}
	rules := denyRules(renderDenyPatterns(t, layout))
	if len(rules) == 0 {
		t.Fatal("no rules rendered")
	}
	for _, blocked := range []string{
		"cat /etc/faramir/age.key",
		"rm /var/log/faramir/audit.log",
		"cat /srv/luks.key",
	} {
		if !matchesAny(t, rules, blocked) {
			t.Errorf("%q is not refused; the rules cover less than they claim", blocked)
		}
	}
	for _, allowed := range []string{
		"cat /etc/faramir-notes.md",
		"cat /var/log/faramir-other/x",
		"cat /srv/luks.key.md",
		"rm /usr/local/libexec/faramir-tools/x",
	} {
		if matchesAny(t, rules, allowed) {
			t.Errorf("%q is refused by a rule about a neighbouring path", allowed)
		}
	}
}

// Every entry renders a rule with no verb in it, strict or not: the guard
// refuses a declared path named at all. So an entry carrying --strict renders
// what every other entry does, and the flag's difference is on the brokered
// route, which internal/broker holds it to.
//
// Asserted by what the rendered file decides rather than by the shape of a
// pattern: what the operator asked for is that `ls` be refused.
func TestAnStrictEntryRefusesACommandWithNoVerbInIt(t *testing.T) {
	layout := testLayout()
	layout.Blocked = []config.BlockedPath{
		{Path: "/home/operator/.private", Strict: true},
		{Path: "/srv/keys/luks.key"},
	}

	rules := denyRules(renderDenyPatterns(t, layout))

	for _, command := range []string{
		"ls -l /home/operator/.private",
		"cat /home/operator/.private/key",
		// The ordinary entry beside it is refused the same way. Strict is no
		// longer a difference here: the guard refuses a declared path named at
		// all, whatever flag the entry carries, so there is no looser reading
		// left for the flag to tighten. What it still separates is the brokered
		// route, which internal/broker holds it to.
		"ls -l /srv/keys/luks.key",
		"cat /srv/keys/luks.key",
	} {
		if !refusedByAny(t, rules, command) {
			t.Errorf("%q is allowed, and it names a declared path", command)
		}
	}
	// And neither entry reaches a sibling that starts the same way.
	for _, command := range []string{
		"ls /home/operator/.private-notes.md",
		"cat /srv/keys/luks.key.bak",
	} {
		if refusedByAny(t, rules, command) {
			t.Errorf("%q is refused, and it names no declared path", command)
		}
	}
}

// A host that declares nothing renders no subject rule. An empty alternation
// matches the empty string, which with no verb in front of it would refuse every
// command an agent ran, so the empty case is the one that must not be written.
func TestAHostThatDeclaresNothingLeavesOrdinaryCommandsAlone(t *testing.T) {
	layout := testLayout()
	layout.Blocked = nil
	layout.Links = nil

	rules := denyRules(renderDenyPatterns(t, layout))

	for _, command := range []string{
		"ls", "make build", "git status", "cat README.md", "ls -l /srv/keys/luks.key",
	} {
		if refusedByAny(t, rules, command) {
			t.Errorf("%q is refused by a host that declared nothing", command)
		}
	}
}

// refusedByAny is whether any rendered rule matches, which is the guard's own
// decision: it walks the file and stops at the first pattern that does.
func refusedByAny(t *testing.T, rules []string, command string) bool {
	t.Helper()
	for _, rule := range rules {
		re, err := regexp.Compile(rule)
		if err != nil {
			t.Fatalf("a rendered rule does not compile: %v (%s)", err, rule)
		}
		if re.MatchString(command) {
			return true
		}
	}
	return false
}
