package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// optionalOperand matches the trailing "[NAME]" of a Use line, which is how a
// command spells an operand it will take one of. "[FILE...]" is not this: the
// dots are a command that takes as many as it is given.
var optionalOperand = regexp.MustCompile(`\[([A-Z][A-Z-]*)\]$`)

// oneOperandCommands walks the tree for the commands that take at most one
// operand, each with the path to reach it. Derived from the tree rather than
// listed here, so a command added with the same shape is covered by having
// been added.
func oneOperandCommands(c *cobra.Command, path []string) [][]string {
	var out [][]string
	for _, sub := range c.Commands() {
		here := append(append([]string{}, path...), sub.Name())
		if fields := strings.Fields(sub.Use); len(fields) > 0 {
			if optionalOperand.MatchString(fields[len(fields)-1]) {
				out = append(out, here)
			}
		}
		out = append(out, oneOperandCommands(sub, here)...)
	}
	return out
}

// A second operand is a typo, and taking it means acting on the first and
// silently dropping the second: `faramir logs a b` reports on a and says
// nothing about b, which reads as though b had no records. Refused as usage,
// and the refusal names the command and what the one operand is for, cobra's
// own message ("accepts at most 1 arg(s), received 2") naming neither.
func TestACommandTakingOneOperandRefusesTwo(t *testing.T) {
	commands := oneOperandCommands(newRootCmd(), nil)
	if len(commands) == 0 {
		t.Fatal("no command takes an optional operand, so this asserts nothing")
	}
	for _, path := range commands {
		t.Run(strings.Join(path, " "), func(t *testing.T) {
			// The error itself, not what cobra wrote: the usage block prints the
			// command's own Use line, so a buffer holds the command's name
			// whether or not the refusal names it.
			var usage bytes.Buffer
			root := newRootCmd()
			root.SetOut(&usage)
			root.SetErr(&usage)
			root.SetArgs(append(append([]string{}, path...), "first", "second"))

			err := root.Execute()
			if code := exitCode(err); code != 2 {
				t.Errorf("exit = %d, want 2 for a second operand", code)
			}
			if err == nil {
				t.Fatal("a second operand was accepted")
			}
			want := "faramir " + strings.Join(path, " ") + " takes at most one "
			if !strings.HasPrefix(err.Error(), want) {
				t.Errorf("the refusal is %q, want it to open with %q", err, want)
			}
		})
	}
}

// And the operand it does take is still accepted, or the check above would pass
// against a command that refuses every invocation.
func TestACommandTakingOneOperandStillTakesOne(t *testing.T) {
	for _, path := range oneOperandCommands(newRootCmd(), nil) {
		t.Run(strings.Join(path, " "), func(t *testing.T) {
			var out bytes.Buffer
			root := newRootCmd()
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(append(append([]string{}, path...), "only"))
			// What it then does needs a broker, a config or root, so the exit
			// status is not the subject: that it was not refused as usage is.
			if code := exitCode(root.Execute()); code == 2 {
				t.Errorf("one operand was refused as a wrong invocation: %q", out.String())
			}
		})
	}
}
