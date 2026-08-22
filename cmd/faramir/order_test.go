package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/cli"
)

// treeOrder is the position of every subcommand in the order the help prints
// them, which is the order the command tree is assembled in. The tree is the
// one of the three lists that a reader actually sees, so it is the one the
// other two follow.
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

// The two groups above it are ordered for a reader working through them: the
// commands group leads with `run`, and provisioning follows an install from
// `init` to `uninstall`. This group is neither, so it is sorted, and a command
// appended to the end of it is a command out of place.
func TestTheInternalGroupIsSorted(t *testing.T) {
	root := newRootCmd()
	var names []string
	for _, c := range root.Commands() {
		if c.GroupID == groupInternal {
			names = append(names, c.Name())
		}
	}
	if len(names) < 2 {
		t.Fatalf("found %d internal commands, too few to be an order", len(names))
	}
	if !slices.IsSorted(names) {
		t.Errorf("the internal group is %v, want it sorted", names)
	}
}
