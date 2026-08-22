package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Colour must not move a column. text/tabwriter measures the bytes it is given,
// so a painted cell widens its column by the length of its escape codes and
// every column after it slides; this is what printTable exists to avoid, and
// the failure is invisible until somebody looks at a terminal.
func TestPaintDoesNotMoveAColumn(t *testing.T) {
	on := palette{on: true}
	rows := func(p palette) [][]cell {
		return [][]cell{
			{painted("KIND", p.key), painted("ENTRY", p.key), painted("COVERS", p.key)},
			{painted("path", p.bold), value("/a"), painted("file tools", p.dim)},
			{painted("command", p.bold), value("/much/longer/entry"), painted("commands", p.dim)},
		}
	}
	var painted, plainOut bytes.Buffer
	printTable(&painted, rows(on))
	printTable(&plainOut, rows(palette{}))

	stripped := ansi.ReplaceAllString(painted.String(), "")
	if stripped != plainOut.String() {
		t.Errorf("painted output does not match the plain one once the escapes are\n"+
			"taken out, so the colour moved a column:\n%q\n%q", stripped, plainOut.String())
	}
	// And the columns really do line up, which the comparison above would not
	// catch if both were wrong in the same way.
	lines := strings.Split(strings.TrimRight(plainOut.String(), "\n"), "\n")
	starts := make([]int, 0, len(lines))
	for _, line := range lines {
		starts = append(starts, strings.Index(line, strings.Fields(line)[1]))
	}
	for i, at := range starts {
		if at != starts[0] {
			t.Errorf("row %d starts its second column at %d, want %d", i, at, starts[0])
		}
	}
}

// A cell the operator wrote is never painted: the colour stops where faramir's
// own words stop, so a value cannot dress itself as one of them.
func TestAValueIsNeverPainted(t *testing.T) {
	on := palette{on: true}
	var out bytes.Buffer
	printTable(&out, [][]cell{{painted("KIND", on.key), value("\x1b[31mnot faramir's")}})
	line := out.String()
	if strings.Count(line, "\x1b[") != 3 {
		t.Errorf("want the header's two escapes and the value's own one, got %q", line)
	}
	if strings.Contains(ansi.ReplaceAllString(line, ""), "KIND\x1b") {
		t.Error("the header ran into the value")
	}
}
