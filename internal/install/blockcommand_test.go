package install

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// A declared command is the words, taken literally, with any run of whitespace
// between them. Not a pattern the operator writes: a language here would be a
// second thing to get wrong in a file that decides what an agent may run, and
// both failures are silent.
func TestADeclaredCommandIsTheWords(t *testing.T) {
	for command, want := range map[string]string{
		"op read":       `\bop\s+read\b`,
		"sops -d":       `\bsops\s+-d\b`,
		"pass show":     `\bpass\s+show\b`,
		"vault kv":      `\bvault\s+kv\b`,
		"terraform":     `\bterraform\b`,
		"op  read":      `\bop\s+read\b`,
		"a.b c":         `\ba\.b\s+c\b`,
		"gh auth token": `\bgh\s+auth\s+token\b`,
	} {
		if got := BlockedCommandRule(command); got != want {
			t.Errorf("%q rendered %q, want %q", command, got, want)
		}
	}
}

// It reaches the command guard and nothing else: a command is not a path, so no
// agent's file-tool rules can carry one.
func TestADeclaredCommandReachesTheGuardAlone(t *testing.T) {
	layout := Layout{
		ConfigDir: "/etc/faramir",
		Blocked: []config.BlockedPath{
			{Command: "op read"},
			{Command: "sops -d"},
			{Name: "*.pem"},
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
		{"echo op read", true, "wherever it appears on the line"},
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
			if rule == "Read(**/"+word+")" {
				t.Errorf("a command reached Claude Code's rules as %q", rule)
			}
		}
	}
}

// An entry is in force when the add reports it, not after the next install.
// Both files an entry feeds are rendered by the steps a `block` run applies:
// the agents' own rule files, and the one the command guard reads. Without the
// second, `block add --command` reported changed and the agent's shell could
// still run the command, a command entry having no file-tool half at all.
func TestABlockRunRendersBothEntryPoints(t *testing.T) {
	var run runner
	var agents, patterns bool
	for _, step := range run.BlockedSteps() {
		switch step.name {
		case labelAgentConfig:
			agents = true
		case "deny patterns":
			patterns = true
		}
	}
	if !agents {
		t.Error("a block run does not render the agents' rule files")
	}
	if !patterns {
		t.Error("a block run does not render the file the command guard reads")
	}
	// A link is a subject in both too.
	patterns = false
	for _, step := range run.LinkSteps() {
		if step.name == "deny patterns" {
			patterns = true
		}
	}
	if !patterns {
		t.Error("a link run does not render the file the command guard reads")
	}
}

// A command entry has no path, so nothing stats one: the warning said "` is not
// there`" with an empty path where the path goes, once per command entry on
// every run, which is how a warnings channel stops being read.
func TestACommandEntryWarnsAboutItselfRatherThanAnEmptyPath(t *testing.T) {
	var report Report
	blockedWarnings(&report, config.BlockedPath{Command: "op read"}, nil)
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %v, want one", report.Warnings)
	}
	got := report.Warnings[0]
	if strings.Contains(got, "is not there") {
		t.Errorf("a command entry was stat'ed as a path: %s", got)
	}
	if !strings.Contains(got, "op read") {
		t.Errorf("the warning does not name the command: %s", got)
	}
}
