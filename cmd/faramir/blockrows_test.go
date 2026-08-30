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

// Every built-in goes under the table, whatever its kind. The two halves are
// sorted separately, so one table holding both puts a seam in the middle of a
// sorted column with nothing to say it is there, and leaves no way to see
// which rows `block rm` will refuse.
func TestEveryBuiltInRuleGoesUnderTheTable(t *testing.T) {
	rows := blockRows(t.TempDir(), []config.BlockedPath{{Path: "/srv/luks.key"}}, true)
	kinds := map[string]int{}
	for _, row := range rows {
		if row.Source == sourceBuiltIn {
			if !row.belowTable() {
				t.Errorf("built-in %s rule %q was put in the table", row.Kind, row.Entry)
			}
			kinds[row.Kind]++
			continue
		}
		if row.belowTable() {
			t.Errorf("declared entry %q was printed under the table", row.Entry)
		}
	}
	// Both kinds of built-in, each of which is printed as its own section.
	for _, kind := range []string{kindPath, kindCommand} {
		if kinds[kind] == 0 {
			t.Errorf("no built-in %s rules listed, so this test asserts nothing", kind)
		}
	}
}

// Every form the config accepts is listed. A form that renders a rule but no
// row is a rule nothing can be asked about.
func TestEveryDeclaredFormIsListed(t *testing.T) {
	declared := []config.BlockedPath{
		{Path: "/srv/luks.key"},
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

// Strictness is what decides whether a command that only names the path can
// run at all, so it is a field rather than a phrase inside Detail: a caller
// filtering the listing should not have to read prose to learn it, and the
// table marks the kind cell from the same field.
func TestAStrictEntryIsListedAsStrict(t *testing.T) {
	rows := blockRows(t.TempDir(), []config.BlockedPath{
		{Path: "/srv/luks.key", Strict: true},
		{Path: "/srv/loose.key"},
	}, false)
	got := map[string]bool{}
	for _, row := range rows {
		got[row.Entry] = row.Strict
	}
	if !got["/srv/luks.key"] {
		t.Error("a --strict entry is not listed as strict, so the listing cannot " +
			"say why naming it is refused")
	}
	if got["/srv/loose.key"] {
		t.Error("an ordinary entry is listed as strict, which reports a refusal " +
			"this host does not make")
	}
}
