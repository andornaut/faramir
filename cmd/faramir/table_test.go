package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/install"
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
	printTable(&out, [][]cell{{painted("KIND", on.key), value("not faramir's")}})
	line := out.String()
	if strings.Count(line, "\x1b[") != 2 {
		t.Errorf("want the header's two escapes and no others, got %q", line)
	}
	if strings.Contains(ansi.ReplaceAllString(line, ""), "KIND\x1b") {
		t.Error("the header ran into the value")
	}
}

// A value is somebody else's text and a terminal obeys what it is sent, so an
// escape in one is drawn rather than acted on. A bare carriage return returns
// the cursor and the rest of the row overwrites what came before it, which
// would make a listing show an entry other than the one stored; ESC c resets
// the terminal and takes the scrollback with it on many emulators.
func TestAValueCannotReachTheTerminal(t *testing.T) {
	for _, text := range []string{
		"evil\rSAFE-LOOKING", "boom\x1bc", "t\x1b]0;pwned\a",
		"two\nlines", "a\tb", "c1\u009b2J",
	} {
		var out bytes.Buffer
		printTable(&out, [][]cell{{value(text)}})
		line := out.String()
		if body, _ := strings.CutSuffix(line, "\n"); strings.IndexFunc(body, func(r rune) bool {
			return r < 0x20 || (r >= 0x7f && r <= 0x9f)
		}) >= 0 {
			t.Errorf("%q reached the terminal as %q", text, line)
		}
	}
}

// And the columns line up when a cell is drawn wider or narrower than its rune
// count: a CJK ideograph takes two columns, a combining mark none. Counting
// runes leaves every column after such a cell out by the difference.
//
// Asserted against the exact line rather than by measuring the output with
// width(), which is the function under test: an error there would shift the
// padding and the measurement together and cancel itself out. All three cells
// below are six columns wide and three different rune counts, so each one is
// padded by exactly the two spaces that separate columns.
func TestColumnsAlignAtTheWidthATerminalDraws(t *testing.T) {
	for _, first := range []string{
		"\u65e5\u672c\u8a9e", // three runes, six columns
		"abcdef",             // six of each
		"e\u0301abcde",       // seven runes, six columns
	} {
		var out bytes.Buffer
		printTable(&out, [][]cell{{value(first), value("x")}})
		if got, want := out.String(), first+"  x\n"; got != want {
			t.Errorf("printTable(%q) = %q, want %q", first, got, want)
		}
	}
	// And together, where the widest decides: every second column starts in the
	// same place, so every line is the same length.
	var out bytes.Buffer
	printTable(&out, [][]cell{
		{value("\u65e5\u672c\u8a9e"), value("a")},
		{value("ab"), value("b")},
	})
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	if want := "\u65e5\u672c\u8a9e  a"; lines[0] != want {
		t.Errorf("wide row = %q, want %q", lines[0], want)
	}
	if want := "ab      b"; lines[1] != want {
		t.Errorf("narrow row = %q, want %q: it pads to the six columns the wide "+
			"cell draws, not to its three runes", lines[1], want)
	}
}

// doctor's detail carries a path from the config and an error string from the
// host, and a filename may hold anything the filesystem accepts. A terminal
// obeys what it is sent, so a carriage return in a detail would overwrite the
// status beside it, on the one command an operator runs to find out whether the
// install is sound.
func TestADoctorDetailCannotReachTheTerminal(t *testing.T) {
	report := install.DoctorReport{Findings: []install.Finding{
		{Name: "config", Status: install.StatusFailed, Detail: "cannot read /etc/f\rSAFE/x"},
		{Name: "secrets", Status: install.StatusWarn, Detail: "a file named boom\x1bc will not load"},
		{Name: "store", Status: install.StatusWarn, Detail: "a title\x1b]0;pwned\a here"},
	}}
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, report)
	if i := strings.IndexFunc(out.String(), func(r rune) bool {
		return (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r <= 0x9f)
	}); i >= 0 {
		t.Errorf("a control character reached the terminal at %d: %q", i, out.String())
	}
}

// And an ordinary detail keeps its words. Compared with the wrapping taken back
// out: a detail longer than the terminal is laid out across lines, which is the
// layout doing its job rather than the escaping changing the text.
func TestAnOrdinaryDoctorDetailKeepsItsWords(t *testing.T) {
	const detail = "/etc/faramir/config.toml is what this install renders: 12 rule(s)"
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "deny patterns", Status: install.StatusOK, Detail: detail},
	}})
	got := strings.Join(strings.Fields(out.String()), " ")
	if !strings.Contains(got, strings.Join(strings.Fields(detail), " ")) {
		t.Errorf("an ordinary detail was changed: %q", out.String())
	}
}

// The removal prompt shows the file an operator is about to destroy and takes
// its name back as the answer. A filename may hold anything the filesystem
// accepts, so a carriage return in one would show a path other than the file
// being deleted, on the one prompt where getting it wrong is unrecoverable.
func TestTheRemovalPromptCannotBeDressedUp(t *testing.T) {
	for _, name := range []string{
		"ev\ril-SAFE-LOOKING.sops.yml", "boom\x1bc.sops.yml", "t\x1b]0;x\a.sops.yml",
	} {
		if got := safe("/etc/faramir/secrets/" + name); strings.IndexFunc(got, func(r rune) bool {
			return (r < 0x20 && r != '\n') || (r >= 0x7f && r <= 0x9f)
		}) >= 0 {
			t.Errorf("%q still reaches the terminal as %q", name, got)
		}
	}
}
