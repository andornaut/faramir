package cli_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/cli"
)

// The README groups the operator's commands into a table, which is where a
// reader finds out what exists. A command added to cli.Operator and left out of
// it is one nothing tells them about: the deny rules refuse it to the agent, so
// it is the operator's, and the operator is the one reading this.
//
// Read from the embedded README rather than from the working tree, which is the
// copy an install writes out and so the one an operator on a host has.
func TestTheReadmeGroupsEveryOperatorCommand(t *testing.T) {
	body, err := faramir.Assets.ReadFile("README.md")
	if err != nil {
		t.Skipf("the README is not embedded here: %v", err)
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
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z][\\w -]*)`").FindAllStringSubmatch(table, -1) {
		listed[m[1]] = true
	}
	var missing []string
	for _, name := range cli.OperatorOnly() {
		if !listed[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		t.Errorf("the README group table names none of %v, so nothing tells an "+
			"operator these exist", missing)
	}
}
