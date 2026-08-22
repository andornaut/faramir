package main

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// A declared command is a literal the operator wrote. Printed under the table
// it loses its source, and `block ls` then reports what this host declared as
// one of the rules faramir carries: the operator looks for the entry that put
// it there and finds none.
func TestADeclaredCommandStaysInTheTable(t *testing.T) {
	rows := blockRows(t.TempDir(), []config.BlockedPath{{Command: "op read"}}, false)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want the one declared entry", len(rows))
	}
	if rows[0].Source != sourceDeclared {
		t.Errorf("a declared command is sourced %q, want %q", rows[0].Source, sourceDeclared)
	}
	if rows[0].belowTable() {
		t.Error("a declared command was printed under the table, where it reads as " +
			"one of the rules faramir carries rather than as this host's own")
	}
}

// The built-in command rules are regular expressions, one long enough that a
// cell holding it would take the alignment of every other row with it.
func TestTheBuiltInCommandRulesGoUnderTheTable(t *testing.T) {
	rows := blockRows(t.TempDir(), nil, true)
	var commands, table int
	for _, row := range rows {
		if row.Kind != kindCommand {
			table++
			continue
		}
		if !row.belowTable() {
			t.Errorf("built-in command rule %q was put in the table", row.Entry)
		}
		commands++
	}
	if commands == 0 {
		t.Error("no built-in command rules listed, so this test asserts nothing")
	}
	if table == 0 {
		t.Error("no table rows listed; the built-in directories should be there")
	}
}

// Every form the config accepts is listed. A form that renders a rule but no
// row is a rule nothing can be asked about.
func TestEveryDeclaredFormIsListed(t *testing.T) {
	declared := []config.BlockedPath{
		{Path: "/srv/luks.key"},
		{Name: "*.pem"},
		{Command: "op read"},
	}
	rows := blockRows(t.TempDir(), declared, false)
	if len(rows) != len(declared) {
		t.Fatalf("got %d rows for %d entries", len(rows), len(declared))
	}
	for i, row := range rows {
		if row.Entry == "" {
			t.Errorf("row %d has no entry", i)
		}
		if row.Source != sourceDeclared {
			t.Errorf("row %d is sourced %q, want %q", i, row.Source, sourceDeclared)
		}
	}
}
