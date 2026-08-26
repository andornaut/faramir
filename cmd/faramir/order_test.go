package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/cli"
)

// treeOrder is the position of every subcommand in the order the help prints
// them, which is alphabetical within each group. The tree is the one of the
// three lists that a reader actually sees, so it is the one the other two
// follow.
func treeOrder(t *testing.T) map[string]int {
	t.Helper()
	at := map[string]int{}
	for i, name := range dispatcherNames(t) {
		at[name] = i
	}
	return at
}

// cli.Operator is read beside the help by anybody adding a command, and its
// order is otherwise free to drift: nothing downstream depends on it, since
// OperatorOnly feeds an alternation where order does not decide a match. Two
// lists of the same commands in two orders is a reader wondering which one is
// meaningful, so this holds it to the one that is.
func TestTheOperatorListFollowsTheOrderTheHelpPrints(t *testing.T) {
	at := treeOrder(t)
	previous, previousName := -1, ""
	checked := 0
	for _, name := range cli.Operator {
		// cobra's own two are appended while the root executes rather than
		// declared with the rest, so they sit at the end of the tree whatever
		// group the help prints them in. Their place in cli.Operator is beside
		// `version`, which is the adjacency the comment there is about.
		if name == "help" || name == "completion" {
			continue
		}
		i, ok := at[name]
		if !ok {
			t.Errorf("cli.Operator names %q, which the command tree does not carry", name)
			continue
		}
		checked++
		if i < previous {
			t.Errorf("cli.Operator has %q before %q; the help prints them the other "+
				"way round", previousName, name)
		}
		previous, previousName = i, name
	}
	if checked == 0 {
		t.Fatal("no name in cli.Operator is a subcommand, so this asserts nothing")
	}
}

// The README groups the same commands by task rather than by who runs them, so
// its rows are its own. Within a row the order is still the tree's: a reader
// who has met `vault add` in the help and looks the group up here should not
// find its siblings rearranged.
func TestTheReadmeGroupTableFollowsTheSameOrderWithinEachRow(t *testing.T) {
	body, err := faramir.Assets.ReadFile("README.md")
	if err != nil {
		t.Fatalf("the README is not embedded: %v", err)
	}
	text := string(body)
	start := strings.Index(text, "Group | Commands")
	if start < 0 {
		t.Fatal("the README carries no group table, so this asserts nothing")
	}
	table := text[start:]
	if end := strings.Index(table, "\n\n"); end > 0 {
		table = table[:end]
	}

	at := treeOrder(t)
	command := regexp.MustCompile("`([a-z][a-z -]*)`")
	rows := 0
	for _, row := range strings.Split(table, "\n")[2:] {
		var named []string
		for _, m := range command.FindAllStringSubmatch(row, -1) {
			if _, ok := at[m[1]]; ok {
				named = append(named, m[1])
			}
		}
		if len(named) < 2 {
			continue
		}
		rows++
		previous, previousName := -1, ""
		for _, name := range named {
			if at[name] < previous {
				t.Errorf("the README row %q lists %q before %q; the help prints them "+
					"the other way round", strings.SplitN(row, "|", 2)[0], previousName, name)
			}
			previous, previousName = at[name], name
		}
	}
	if rows == 0 {
		t.Fatal("no README row names two commands, so this asserts nothing")
	}
}

// Sorted to the leaf, not only at the top: a reader who opens `faramir vault
// --help` is looking a verb up the same way.
func TestEverySubcommandListIsSorted(t *testing.T) {
	checked := 0
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		names := make([]string, 0, len(c.Commands()))
		for _, sub := range c.Commands() {
			names = append(names, sub.Name())
			walk(sub)
		}
		if len(names) < 2 {
			return
		}
		checked++
		if !slices.IsSorted(names) {
			t.Errorf("%s lists %v, want it sorted", c.CommandPath(), names)
		}
	}
	walk(newRootCmd())
	if checked == 0 {
		t.Fatal("no command groups others, so this asserts nothing")
	}
}
