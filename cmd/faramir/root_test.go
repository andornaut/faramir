package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/cli"
)

// A subcommand the dispatcher accepts but neither cli.Operator nor cli.Internal
// names would have its arguments scanned.
func TestEverySubcommandIsNamedForTheGuard(t *testing.T) {
	named := map[string]bool{}
	for _, name := range append(append([]string{}, cli.Operator...), cli.Internal...) {
		named[name] = true
	}

	have := map[string]bool{}
	for _, c := range dispatcherNames(t) {
		have[c] = true
		if !named[c] {
			t.Errorf("%q is a subcommand but is in neither cli.Operator nor cli.Internal", c)
		}
	}
	// And the other way round: a name the lists still carry for a command that
	// no longer exists sanctions arguments that nothing scans.
	for name := range named {
		if !have[name] {
			t.Errorf("cli names %q, which is no longer a subcommand", name)
		}
	}
}

// The listing is one column of descriptions, and `help` and `completion` are
// cobra's: it writes "Help about any command", so a lowercase description
// beside that one reads as a command of a different kind rather than as one
// this project wrote. Sentence case throughout, cobra's own included, which is
// what nothing but this holds a new command to.
func TestEveryCommandIsDescribedInSentenceCase(t *testing.T) {
	root := newRootCmd()
	// cobra adds `help` and `completion` while executing, not while building.
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("assembling the root: %s", err)
	}

	checked := 0
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			checked++
			first, _ := utf8.DecodeRuneInString(sub.Short)
			switch {
			case sub.Short == "":
				t.Errorf("%s carries no description, so the listing has a blank row",
					sub.CommandPath())
			case !unicode.IsUpper(first):
				t.Errorf("%s is described as %q, which opens in lower case where "+
					"cobra's own do not", sub.CommandPath(), sub.Short)
			}
			walk(sub)
		}
	}
	walk(root)
	if checked == 0 {
		t.Fatal("the root carries no subcommands, so this asserts nothing")
	}
}

// dispatcherNames returns every subcommand the root carries. Taken from the
// assembled command tree rather than from the source, so a command registered
// anywhere is seen.
func dispatcherNames(t *testing.T) []string {
	t.Helper()
	root := newRootCmd()
	// cobra adds `help` and `completion` while executing, not while building.
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("assembling the root: %s", err)
	}

	// A command that groups others contributes its children rather than itself,
	// spelled the way cli.Operator spells them: the guard matches what a person
	// types, and nobody types a bare `faramir vault`. To the leaf, however deep,
	// a walk that stopped short leaving those children out of the list the
	// sanction is built from.
	var names []string
	var walk func(prefix string, c *cobra.Command)
	walk = func(prefix string, c *cobra.Command) {
		// cobra's own, and the only two whose children are not faramir's: the
		// shells `completion` generates for are not subcommands anybody names here.
		if c.Name() == "completion" || c.Name() == "help" {
			names = append(names, c.Name())
			return
		}
		name := strings.TrimSpace(prefix + " " + c.Name())
		children := c.Commands()
		if len(children) == 0 {
			names = append(names, name)
			return
		}
		for _, child := range children {
			walk(name, child)
		}
	}
	for _, c := range root.Commands() {
		walk("", c)
	}
	if len(names) < 10 {
		t.Fatalf("found only %d subcommands; the root was not assembled", len(names))
	}
	return names
}

// `deny` needs no id: only one question is ever outstanding. The asymmetry
// with approving is deliberate -- refusing something unseen is safe, and an
// escalation that names no command is one nobody judged. Each stops at the
// root check rather than dialling a socket, which is enough to tell a usage
// error from an argument that was accepted.
func TestRejectNeedsNoIDAndApproveDoes(t *testing.T) {
	if code := runCommand(newRejectCmd(), nil); code == 2 {
		t.Error("faramir sudo reject = 2, want it accepted without an id")
	}
	if code := runCommand(newRejectCmd(), []string{"9f2a1c"}); code == 2 {
		t.Error("faramir sudo reject ID = 2, want an id accepted too")
	}
	if code := runCommand(newApproveCmd(), nil); code != 2 {
		t.Errorf("faramir sudo approve = %d, want 2: a yes has to name the command it is for", code)
	}
	if code := runCommand(newApproveCmd(), []string{"9f2a1c"}); code == 2 {
		t.Error("faramir sudo approve ID = 2, want it accepted")
	}
	// Listing and watching take no id at all: the verbs are their own commands.
	if code := runCommand(newSudoListCmd(), []string{"9f2a1c"}); code != 2 {
		t.Errorf("faramir sudo ls ID = %d, want 2: it lists and answers nothing", code)
	}
	if code := runCommand(newSudoWatchCmd(), []string{"9f2a1c"}); code != 2 {
		t.Errorf("faramir sudo watch ID = %d, want 2: it answers from the terminal", code)
	}
}

// A command that ran and failed says nothing of its own. exitCodeError carries
// a status the command has already explained on its own stderr, so a second line
// naming it is faramir talking over the output the caller came for: a brokered
// command that exited 3 would otherwise have "Error: exit status 3" appended to
// what it printed. The status still reaches the caller as the exit code.
func TestAFailedCommandPrintsNoErrorOfItsOwn(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	// `version` is reached without a broker, and its RunE is replaced with the
	// one thing under test: a status returned once the arguments are accepted.
	for _, c := range root.Commands() {
		if c.Name() == "version" {
			c.RunE = func(*cobra.Command, []string) error { return codeErr(3) }
		}
	}
	root.SetArgs([]string{"version"})
	if code := exitCode(root.Execute()); code != 3 {
		t.Errorf("exit = %d, want 3: the child's status is what the caller reads", code)
	}
	if out.Len() != 0 {
		t.Errorf("wrote %q, want nothing: the command has already explained itself", out.String())
	}
}

// A parse error names a flag the way the reader has to type it: two dashes for
// a long name, one for a single-letter shorthand. Checked through the root,
// because what matters is the spelling that reaches the operator's stderr, and
// an operator told about "-env-file" would try one faramir does not accept.
func TestAParseErrorSpellsAFlagTheWayItIsTyped(t *testing.T) {
	for _, c := range []struct{ name, arg, want string }{
		{"long name", "--bogus", "unknown flag: --bogus"},
		{"shorthand", "-Z", "unknown shorthand flag: 'Z' in -Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// One buffer, and it cannot be two: cobra writes usage to OutOrStderr(),
			// which is stderr only while SetOut is unset, so a test that captures
			// stdout by setting it pulls the usage block into its own capture. That
			// stdout stays clean is asserted in check-disclose.sh, against the real
			// binary and real file descriptors.
			var out bytes.Buffer
			root := newRootCmd()
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"status", c.arg})
			if code := exitCode(root.Execute()); code != 2 {
				t.Errorf("exit = %d, want 2 for a wrong invocation", code)
			}
			if !strings.Contains(out.String(), c.want) {
				t.Errorf("wrote %q, want it to contain %q", out.String(), c.want)
			}
		})
	}
}

// No two commands describe themselves the same way. A group and one of its
// subcommands sharing a line is the case this catches: `faramir reader` and
// `faramir reader ls` both read "Who can decrypt the managed store", so the
// listing gave the same answer to two different questions and neither said
// what it did that the other did not.
func TestNoTwoCommandsShareADescription(t *testing.T) {
	root := newRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("assembling the root: %s", err)
	}
	seen := map[string]string{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			// cobra writes its own for these two, and writes them once.
			if name := sub.Name(); name != "help" && name != "completion" {
				if first, dup := seen[sub.Short]; dup {
					t.Errorf("%s and %s are both described as %q",
						first, sub.CommandPath(), sub.Short)
				} else {
					seen[sub.Short] = sub.CommandPath()
				}
			}
			walk(sub)
		}
	}
	walk(root)
	if len(seen) < 20 {
		t.Fatalf("only %d description(s) collected; the root was not assembled", len(seen))
	}
}
