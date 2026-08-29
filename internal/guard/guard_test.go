package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/denyrules"
)

// The whole package runs against this tree's patterns file, rendered as an
// install would render it: the shipped copy is a template whose path rules
// match nothing unexpanded. Every step exits rather than carrying on, because
// an unset variable sends the guard to whatever is installed under
// /usr/local/libexec, and the suite then reports on that build instead of this
// one.
func TestMain(m *testing.M) {
	data, err := renderShippedBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot render the shipped patterns: %v\n", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "faramir-guard-patterns")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot make a directory for them: %v\n", err)
		os.Exit(1)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "deny-patterns.txt")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		cleanup()
		fmt.Fprintf(os.Stderr, "cannot write them: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("FARAMIR_DENY_PATTERNS", path); err != nil {
		cleanup()
		fmt.Fprintf(os.Stderr, "cannot point the guard at them: %v\n", err)
		os.Exit(1)
	}
	// Not deferred: os.Exit would skip it.
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// The prefix sanctions the operator's subcommands, not the roles systemd runs.
// Both spellings, since an unconverged host still has the old per-role
// binaries.
func TestTheDaemonsAreNotSanctionedByThePrefix(t *testing.T) {
	cmds := make([]string, 0, len(cli.Internal)*2)
	for _, role := range cli.Internal {
		cmds = append(cmds,
			"sudo faramir "+role+" --check",
			"sudo faramir-"+role+" --check",
		)
	}
	for _, cmd := range cmds {
		if _, denied := decide(cmd); !denied {
			t.Errorf("the prefix sanctioned a daemon invocation: %q", cmd)
		}
	}
}

// Answering an escalation is the operator's, and this hook gates the agent's
// shell rather than the operator's terminal: an agent that could approve the
// request it raised is the whole boundary gone. Both the helper sudo runs and
// the subcommand a human types are denied here, privileged or not.
func TestTheAgentCannotAnswerItsOwnEscalation(t *testing.T) {
	for _, cmd := range []string{
		"sudo faramir sudo ls",
		"sudo faramir sudo watch",
		"sudo faramir sudo approve",
		"sudo faramir sudo approve a1b2c3",
		"sudo -n faramir sudo approve a1b2c3",
		"sudo faramir sudo reject",
		"sudo faramir sudo reject a1b2c3",
		"sudo faramir pam-escalate",
		// Unprivileged too. It would reach a broker that refuses it, but a
		// refusal here says why, where SO_PEERCRED says only that it failed.
		"faramir sudo ls",
		"faramir sudo watch",
		"faramir sudo approve a1b2c3",
		"faramir sudo reject a1b2c3",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("the agent may answer an escalation: %q", cmd)
		}
	}
}

// The agent may run four subcommands, and their arguments are the only ones the
// deny rules do not scan. Naming them is only safe if every one is named: one
// left out has its arguments scanned, and `run`'s arguments are somebody else's
// command.
func TestEveryAgentSubcommandIsSanctioned(t *testing.T) {
	if len(cli.Agent) == 0 {
		t.Fatal("no subcommand is sanctioned, so this asserts nothing")
	}
	for _, name := range cli.Agent {
		// A ref in the arguments is the thing an unsanctioned call trips on.
		cmd := "faramir " + name + " --env A=faramir://a"
		if pattern, denied := decide(cmd); denied {
			t.Errorf("wrongly denied a sanctioned subcommand: %q (pattern %q)", cmd, pattern)
		}
	}
}

// And everything else faramir offers is refused to this shell, with sudo and
// without. These act on the install rather than through it: the account the
// agent runs as could not carry them out, so what the refusal saves is the
// detour of learning that from a permission error and trying to get around it.
func TestEveryOperatorSubcommandIsRefused(t *testing.T) {
	if len(cli.OperatorOnly()) == 0 {
		t.Fatal("every subcommand is sanctioned to the agent, so this asserts nothing")
	}
	for _, name := range cli.OperatorOnly() {
		for _, cmd := range []string{"faramir " + name, "sudo faramir " + name} {
			if _, denied := decide(cmd); !denied {
				t.Errorf("the agent may run %q, which is the operator's", cmd)
			}
		}
	}
}

// A patterns file that cannot be read must not disable the hook.
func TestFallbackIsUsedWhenThePatternsFileIsMissing(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	if _, denied := decide("sops -d /etc/faramir/secrets/db.sops.yml"); !denied {
		t.Error("the fallback list did not apply")
	}
}

// A pattern that fails to compile is skipped at load, silently weakening the
// list.
func TestEveryFallbackPatternCompiles(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	if got, want := len(loadPatterns()), len(fallback); got != want {
		t.Errorf("%d of %d fallback patterns compiled; the rest are RE2-incompatible", got, want)
	}
}

// The fallback names the compiled defaults and nothing else, so an install
// placed anywhere else is refused by the derived rule alone. The directory is
// taken from where the daemons take it, so moving the config moves what the
// hook refuses instead of silently narrowing it.
func TestTheFallbackFollowsAMovedConfigDir(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	const moved = "/srv/elsewhere"
	command := "cat " + moved + "/config.toml"

	// Nothing else in the list matches this, so what follows is the derived
	// rule and not a coincidence.
	if _, denied := decide(command); denied {
		t.Fatalf("%q is already denied, so this test proves nothing", command)
	}

	t.Setenv("FARAMIR_CONFIG", moved+"/config.toml")

	if _, denied := decide(command); !denied {
		t.Errorf("%q is allowed with the config at %s", command, moved)
	}
	if _, denied := decide("rm -rf " + moved + "/secrets"); !denied {
		t.Error("writes to a moved config directory are allowed")
	}
}

// A config directory this install does not have is refused by nothing, which is
// the same answer the agents' own rules give: what is refused is where this
// host put its install rather than every place a faramir install could be. A
// second install in another home is that install's to refuse.
func TestAConfigDirectoryThisInstallDoesNotHaveIsNotRefused(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")
	for _, command := range []string{
		"cat /home/someone/.config/faramir/config.toml",
		"rm -f /home/someone/.config/faramir/secrets/x.sops.yml",
	} {
		if pattern, denied := decide(command); denied {
			t.Errorf("%q is denied by %q", command, pattern)
		}
	}
	// This install's own, at the same defaults, still is.
	if _, denied := decide("cat /etc/faramir/config.toml"); !denied {
		t.Error("this install's own config directory is allowed")
	}
}

// A config moved to a directory whose name starts like one the rendered file
// already names still gets its own rules. named() asks whether the list covers
// this install's config directory, and a bare path is a substring of every path
// that starts the same way: /var/lib/faramir would read as already covered by
// the rule about /var/lib/faramir-broker, and the rules that are the only cover
// a moved config has would be skipped.
func TestAConfigDirIsNotReadAsCoveredByALongerPath(t *testing.T) {
	rules := make([]string, 0, len(defaultInstallPaths)*3)
	for _, dir := range defaultInstallPaths {
		rules = append(rules, denyrules.For([]string{denyrules.Dir(dir)})...)
	}
	for _, dir := range []string{"/var/lib/faramir", "/etc/faramir-alt", "/var/log"} {
		if named(rules, dir) {
			t.Errorf("%s was read as already covered, so it would get no rules of "+
				"its own", dir)
		}
	}
	// And the install's own directories are covered, which is what stops the
	// rules being rendered twice.
	for _, dir := range defaultInstallPaths {
		if !named(rules, dir) {
			t.Errorf("%s is in the rendered list and was not recognised", dir)
		}
	}
}

// A config directory under a home is written into the rendered file as the
// alternation of the spellings a shell expands to it. named() asks whether the
// list already covers this install's directory, so it has to ask for the same
// form: asking for the plain one misses it and appends the same five rules
// again, on every Bash call.
func TestAConfigDirUnderAHomeIsRecognisedInTheRenderedForm(t *testing.T) {
	home := guardHome()
	if home == "" {
		t.Skip("no home for this account")
	}
	for _, dir := range []string{
		home + "/.config/faramir", "/etc/faramir", "/var/lib/faramir-broker",
	} {
		rendered := denyrules.For([]string{denyrules.DirUnder(home, dir)})
		if !named(rendered, dir) {
			t.Errorf("%s is in the rendered list and was not recognised, so its rules "+
				"are compiled twice on every call", dir)
		}
	}
	// And the bound still holds, which is what stops a moved config being read as
	// already covered by a rule about a longer path.
	rendered := denyrules.For([]string{denyrules.DirUnder(home, "/var/lib/faramir-broker")})
	if named(rendered, "/var/lib/faramir") {
		t.Error("/var/lib/faramir was read as covered by the rule about " +
			"/var/lib/faramir-broker, so it would get no rules of its own")
	}
}

// The exemption spares faramir's own flags and refs, not a redirect attached to
// the call nor the child command it runs. A redirect is the shell's, and redact
// does not guard what it runs, so both must still be scanned.
func TestExemptionKeepsRedirectsAndChildCommands(t *testing.T) {
	for _, cmd := range []string{
		"faramir redact -- cat /etc/faramir/age.key",
		"faramir redact < /etc/faramir/age.key",
		"faramir status > /etc/faramir/age.key",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("the exemption hid a disclosure: %q was allowed", cmd)
		}
	}
	// The ref before the child command is still spared, and a child that trips
	// nothing is still allowed.
	for _, cmd := range []string{
		"faramir run --env DB=faramir://prod/db -- deploy.sh",
		"faramir run --env A=faramir://a",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("the exemption over-refused %q (pattern %q)", cmd, pattern)
		}
	}
}

// A command is already wrapped only if it is the single wrap invocation. One
// that begins with a wrap invocation and chains more is not, since the chained
// part would run unredacted.
func TestIsWrappedRequiresASingleSegment(t *testing.T) {
	ws := wrapScript()
	for _, cmd := range []string{
		"source " + ws + " 'echo hi'",
		"source " + ws + " --stream 'echo hi' &",
		". " + ws + " 'echo hi'",
	} {
		if !isWrapped(cmd) {
			t.Errorf("a wrapped command was seen as unwrapped: %q", cmd)
		}
	}
	for _, cmd := range []string{
		"source " + ws + " 'make test' && cat build/output.log",
		"source " + ws + " 'make test' | tee log",
		"cat /etc/hostname",
	} {
		if isWrapped(cmd) {
			t.Errorf("a chained command was treated as already wrapped: %q", cmd)
		}
	}
}

// An argv element is a literal word to the program, so a separator inside one is
// not a command break. Joined raw it would split cat from its path into two
// segments and slip the read past the rule; quoted, the read stays in one
// segment and is refused.
func TestArgvArrayCannotSmuggleAReadPastSegmentation(t *testing.T) {
	p := &payload{}
	p.ToolInput.Args = []any{"cat", ";", "/etc/faramir/age.key"}
	command := commandOf(p)
	if _, denied := decide(command); !denied {
		t.Errorf("argv read not denied: commandOf = %q", command)
	}
	// The raw join this quoting replaces evaded the rule, so the fix is load
	// bearing rather than incidental.
	if _, denied := decide("cat ; /etc/faramir/age.key"); denied {
		t.Skip("the two-segment raw form is denied here; the quoted form still holds")
	}
}

// A plain string command is unchanged: no argv array, no quoting.
func TestAPlainStringCommandIsScannedAsWritten(t *testing.T) {
	p := &payload{}
	p.ToolInput.Command = "cat /etc/faramir/age.key"
	if got := commandOf(p); got != "cat /etc/faramir/age.key" {
		t.Errorf("commandOf = %q, want it unchanged", got)
	}
}

// A patterns file whose lines will not compile must not thin the list to
// nothing: the built-in rules stand in, so the guard is no weaker than with a
// missing file.
func TestABadPatternLineFallsBackToTheBuiltinRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny-patterns.txt")
	if err := os.WriteFile(path, []byte("cat (unterminated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", path)
	if _, denied := decide("sops -d /etc/faramir/secrets/db.sops.yml"); !denied {
		t.Error("a bad patterns file left the guard open; want the built-in rules")
	}
}

// A file with one uncompilable line and one good line keeps the good line in
// force: a typo must not disable the rules around it.
func TestABadLineDoesNotDisableTheGoodLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny-patterns.txt")
	if err := os.WriteFile(path,
		[]byte("this is a (broken regex\n\\bprintenv\\b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", path)
	if _, denied := decide("printenv"); !denied {
		t.Error("a bad line disabled the good line beside it; want printenv denied")
	}
}
