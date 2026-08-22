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

// A declared command is the words, taken literally, with any run of whitespace
// between them. Not a pattern the operator writes: a language here would be a
// second thing to get wrong in a file that decides what an agent may run, and
// both failures are silent.
func TestADeclaredCommandIsTheWords(t *testing.T) {
	for command, want := range map[string]string{
		"op read":       commandPosition + `op\s+read\b`,
		"sops -d":       commandPosition + `sops\s+-d\b`,
		"pass show":     commandPosition + `pass\s+show\b`,
		"terraform":     commandPosition + `terraform\b`,
		"op  read":      commandPosition + `op\s+read\b`,
		"a.b c":         commandPosition + `a\.b\s+c\b`,
		"gh auth token": commandPosition + `gh\s+auth\s+token\b`,
	} {
		if got := BlockedCommandRule(command); got != want {
			t.Errorf("%q rendered %q, want %q", command, got, want)
		}
	}
}

// Where a declared command is matched: at a command position, not wherever the
// words happen to appear. The difference is whether an entry is safe to write
// at all, or safe only if it is long enough that no flag on any host carries
// it, which is not a question an operator can answer about a fleet.
func TestADeclaredCommandIsMatchedAtACommandPosition(t *testing.T) {
	layout := Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
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

		{"grep -r 'op read' defaults.yml", false, "a search naming it is not running it"},
		{"echo op read", false, "and nor is echoing it"},
		{"ansible-playbook --ask-become-pass site.yml", false,
			"a flag carrying the word: the case a one-word entry could not be written for"},
		{"vim notes-op-read.md", false, "and a file named after it"},
		{"opera read", false, "a longer command starting the same way"},
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

// The one check that can see a command entry. The blocked paths check compares
// against the agents' rule files, where a command never appears, so without
// this a declared command refused by nothing reads as a converged host: which
// is what it did while `block add` was not rendering the guard's file.
func TestDoctorSeesACommandMissingFromTheGuardsFile(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\ncommand = \"op read\"\n")
	libexec := t.TempDir()
	path := filepath.Join(libexec, "deny-patterns.txt")
	opts := DoctorOptions{ConfigDir: dir}

	// A file rendered without the entry, which is what an add that wrote the
	// config and stopped leaves behind.
	if err := os.WriteFile(path, []byte(regexp.QuoteMeta(dir)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var missing DoctorReport
	reportDenyPatterns(&missing, opts, path)
	if len(missing.Findings) != 1 || missing.Findings[0].Status != StatusFailed {
		t.Fatalf("findings = %+v, want one failure", missing.Findings)
	}
	if !strings.Contains(missing.Findings[0].Detail, "op read") {
		t.Errorf("the finding does not name the command: %s", missing.Findings[0].Detail)
	}

	// And the file this install would actually write, which carries the command
	// among everything else it renders.
	rendered, err := RenderDenyPatterns(ruleLayout(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), BlockedCommandRule("op read")) {
		t.Fatal("the render does not carry the declared command")
	}
	if err := os.WriteFile(path, rendered, 0o644); err != nil {
		t.Fatal(err)
	}
	var present DoctorReport
	reportDenyPatterns(&present, opts, path)
	if len(present.Findings) != 1 || present.Findings[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one ok", present.Findings)
	}

	// A rule nobody renders is untidy rather than unguarded, so it warns.
	if err := os.WriteFile(path, append(rendered, []byte("\n\\bleftover\\b\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	var spare DoctorReport
	reportDenyPatterns(&spare, opts, path)
	if len(spare.Findings) != 1 || spare.Findings[0].Status != StatusWarn {
		t.Errorf("findings = %+v, want one warning", spare.Findings)
	}
}

// Two commands are two entries. They share an empty path and an empty name, so
// an identity that reads only those two fields folds every command an operator
// declares into whichever one they declared first, and `block add --command`
// reports the rest as already blocked while writing none of them.
func TestTwoCommandsAreTwoEntries(t *testing.T) {
	asked := []config.BlockedPath{
		{Command: "op read"},
		{Command: "pass show"},
		{Command: "op read"}, // named twice in one call
		{Command: "vault read"},
	}
	entries, added := foldBlocked(nil, asked)
	if want := []bool{true, true, false, true}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
	want := []string{"op read", "pass show", "vault read"}
	if len(entries) != len(want) {
		t.Fatalf("the set holds %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for i, blocks := range want {
		if got := entries[i].Command; got != blocks {
			t.Errorf("entry %d is %q, want %q", i, got, blocks)
		}
	}
}

// A command and a path are not one entry, the way a path and a name are not.
func TestACommandAndAPathAreNotOneEntry(t *testing.T) {
	entries, added := foldBlocked(
		[]config.BlockedPath{{Path: "/srv/luks.key"}},
		[]config.BlockedPath{{Command: "op read"}, {Name: "op read"}},
	)
	if want := []bool{true, true}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v: a command, a name and a path that read "+
			"alike render different rules", added, want)
	}
	if len(entries) != 3 {
		t.Fatalf("the set holds %d entries, want 3: %+v", len(entries), entries)
	}
}
