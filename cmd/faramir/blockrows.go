package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/guard"
	"github.com/andornaut/faramir/internal/termui"
)

// blockRow is one line of `block ls`, and the JSON a configuration manager
// asserts on. Source and kind are separate fields rather than one string: a
// caller filtering to what it declared should not have to parse prose.
type blockRow struct {
	Source string `json:"source"`
	// Kind is one of two: a path or a command. Where the rule is enforced
	// follows from it rather than being carried beside it: a path is rendered
	// into the agents' file-tool rules and into the command guard's patterns
	// from one set, and a command reaches the guard alone, being nothing a file
	// tool can name.
	Kind  string `json:"kind"`
	Entry string `json:"entry"`
	// Strict is whether naming the entry is refused rather than reading it. A
	// field of its own as well as a phrase in Detail: it decides whether a
	// command that only mentions the path can run at all, which is the question
	// a caller asks most often, and reading it out of prose is not an answer.
	Strict bool `json:"strict,omitempty"`
	// State is whether the path is there, for a path entry alone.
	//
	// JSON only, as Detail is: whether a file happens to exist today is a
	// different question from what this host blocks, and a column answering it
	// made the rows long enough to wrap.
	State string `json:"state,omitempty"`
	// DerivedFrom is the declared path a derived row was resolved out of, empty
	// on every other row. Beside Source rather than only inside Detail, for the
	// reason Strict is a field: which entry takes this one away is a question
	// answered by a value, not by parsing a sentence.
	DerivedFrom string `json:"derived_from,omitempty"`
	// Detail is what a built-in protects or what a pattern matches, whichever
	// the row is.
	Detail string `json:"detail,omitempty"`
}

// strictDetail says which of the two readings an entry gets, and says it
// only for the stricter one: the looser is what every entry means unless the
// operator asked otherwise, and printing it on every row would bury the
// handful that are different.
func strictDetail(detail string, strict bool) string {
	if !strict {
		return detail
	}
	const said = "strict: every mention refused, not only a read"
	if detail == "" {
		return said
	}
	return detail + "; " + said
}

// belowTable is whether a row is printed under the table rather than in it.
// Every built-in is: the table is what this host declared, and the two halves
// are sorted separately, so printing them in one table puts a seam in the
// middle of a sorted column with nothing to say it is there. It also leaves
// the operator no way to see which rows `block rm` will refuse, those being
// faramir's own rather than an entry.
func (r blockRow) belowTable() bool {
	return r.Source == sourceBuiltIn
}

// blockRows is the listing, declared entries first: they are what the
// operator wrote and what a converge acts on, and the built-in list is long
// enough to push them off a screen.
func blockRows(configDir string, declared []config.BlockedPath, builtIn bool) []blockRow {
	rows := make([]blockRow, 0, len(declared)+8)
	declaredFrom := len(rows)
	for _, entry := range declared {
		if entry.Command != "" {
			rows = append(rows, blockRow{
				Source: sourceDeclared, Kind: kindCommand, Entry: entry.Command,
				Detail: "neither the agent's shell nor a brokered command may run it",
			})
			continue
		}
		// A derived entry is in the config like any other and is removed with the
		// path it came from, so it is its own source rather than a declared row
		// with a note: a converge filtering to what it declared would otherwise
		// read one as an entry nobody asked for and take it out.
		source, detail := sourceDeclared, ""
		if entry.DerivedFrom != "" {
			source = sourceDerived
			detail = "another name for " + entry.DerivedFrom + "; removed with the entry for it " +
				"once nothing else names the file"
		}
		rows = append(rows, blockRow{
			Source: source, Kind: kindPath, Entry: entry.Path,
			State:       blockedPathState(entry.Path),
			Strict:      entry.Strict,
			DerivedFrom: entry.DerivedFrom,
			Detail:      strictDetail(detail, entry.Strict),
		})
	}
	// Sorted, so a listing is the same twice running and two hosts diff against
	// each other. Within the half rather than across it: the declared entries
	// come first because that is the half an operator wrote and a configuration
	// manager converges, and one order over the whole table would bury them.
	sortRows(rows[declaredFrom:])
	if !builtIn {
		return rows
	}
	builtInFrom := len(rows)
	// What this install occupies, which is refused without anybody declaring it
	// and is most of what a bare host blocks. Derived from the layout rather
	// than compiled in, so these are the paths this host actually uses.
	//
	// Strict, as denyrules writes them: a brokered command may not name one
	// whatever it would do with it, there being no install for it to manage. A
	// row that left the field off reported the strictest rules this host has as
	// the loosest kind of entry.
	for _, dir := range agentcfg.InstalledDirs(configDir) {
		rows = append(rows, blockRow{
			Source: sourceBuiltIn, Kind: kindPath, Entry: dir, Strict: true,
			Detail: strictDetail("this install's own, and everything under it", true),
		})
	}
	// What faramir blocks for what a command does rather than for what it
	// names. No entry changes these, and nothing else can be asked what they
	// are.
	for _, pattern := range guard.ActionPatterns() {
		rows = append(rows, blockRow{
			Source: sourceBuiltIn, Kind: kindCommand, Entry: pattern,
		})
	}
	sortRows(rows[builtInFrom:])
	return rows
}

// sortRows orders one half of the listing by kind and then by entry. Kind
// first, because it is the column a reader scans: every name together, every
// path together, rather than the order they happened to be written in.
func sortRows(rows []blockRow) {
	slices.SortFunc(rows, func(a, b blockRow) int {
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}
		return strings.Compare(a.Entry, b.Entry)
	})
}

// blockedPathState is whether a declared path is there. The same state `link
// ls` carries, and for the same reason: it changes without anybody touching the
// config, and absent is not a fault here, a rule waiting for a volume being the
// point.
//
// "not there" means the path is not there, so a stat that failed for any other
// reason says so instead: this command needs no root, and a blocked path under
// a directory only root can enter would otherwise read as an entry waiting for
// a volume that is never coming.
func blockedPathState(path string) string {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "not there"
	case err != nil:
		return "cannot tell (" + errReason(err) + ")"
	case info.IsDir():
		return "present (directory)"
	}
	return "present"
}

// The two kinds a row can be, and the two places one can come from.
const (
	// kindPath is a rule about one file on this host.
	kindPath = "path"
	// kindCommand is a rule about what a command does rather than what it names.
	kindCommand = "command"
	// sourceDeclared is a rule this host declared, as against one faramir carries.
	sourceDeclared = "declared"
	// sourceBuiltIn is a rule faramir carries or derives, as against one declared.
	sourceBuiltIn = "built-in"
	// sourceDerived is an entry `block add` resolved out of a declared symlink.
	// Declared in the config and removable, unlike a built-in, but not something
	// a configuration manager's own list names.
	sourceDerived = "derived"
)

// printBuiltIn writes the built-in rules under the table, a section per kind
// and each headed by what it holds. Named as rules rather than as entries:
// nothing declared them and `block rm` refuses them, so calling them entries
// would offer the operator a removal that fails.
//
// above is whether anything was printed already, which is what the blank line
// before a section separates it from: --built-in prints no table, and a
// listing that opens on an empty line reads as one missing its first row.
func printBuiltIn(paint termui.Palette, rows []blockRow, above bool) {
	for _, kind := range builtInKinds(rows) {
		var of []blockRow
		for _, row := range rows {
			if row.Kind == kind {
				of = append(of, row)
			}
		}
		if len(of) == 0 {
			continue
		}
		if above {
			fmt.Println()
		}
		above = true
		fmt.Printf("%d built-in %s rule(s):\n", len(of), kind)
		for _, row := range of {
			fmt.Printf("  %s\n", paint.Dim(row.Entry))
		}
	}
}

// builtInKinds is the kinds to print sections for, in print order: the ones
// named here first and in that order, then anything else in sorted order.
//
// Taken from the rows rather than written out, so a kind added later gets a
// section of its own instead of being dropped from the listing while --json
// goes on carrying it. A rule nobody can enumerate is the thing this command
// exists to prevent.
func builtInKinds(rows []blockRow) []string {
	rest := map[string]bool{}
	for _, row := range rows {
		rest[row.Kind] = true
	}
	var kinds []string
	for _, kind := range []string{kindPath, kindCommand} {
		if rest[kind] {
			kinds = append(kinds, kind)
			delete(rest, kind)
		}
	}
	leftover := slices.Collect(maps.Keys(rest))
	slices.Sort(leftover)
	return append(kinds, leftover...)
}
