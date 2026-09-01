package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/doctor"
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
	report := doctor.Report{Findings: []doctor.Finding{
		{Name: "config", Status: doctor.StatusFailed, Detail: "cannot read /etc/f\rSAFE/x"},
		{Name: "secrets", Status: doctor.StatusWarn, Detail: "a file named boom\x1bc will not load"},
		{Name: "store", Status: doctor.StatusWarn, Detail: "a title\x1b]0;pwned\a here"},
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
	printDiagnosis(&out, palette{}, doctor.Report{Findings: []doctor.Finding{
		{Name: "deny patterns", Status: doctor.StatusOK, Detail: detail},
	}})
	got := strings.Join(strings.Fields(out.String()), " ")
	if !strings.Contains(got, strings.Join(strings.Fields(detail), " ")) {
		t.Errorf("an ordinary detail was changed: %q", out.String())
	}
}

// The removal prompt shows the file an operator is about to destroy, and the
// answer is a bare y, so that path is the whole of what identifies it. A
// filename may hold anything the filesystem accepts, so a carriage return in one
// would show a path other than the file being deleted, on the one prompt where
// getting it wrong is unrecoverable.
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

// Every range wide() draws two columns for, at both of its ends and one rune
// outside each. The test above covers CJK alone, so a range whose bound moved
// by one, or an emoji block dropped altogether, shifts the padding of every
// column after it and nothing here would have said so.
func TestWideCoversEachRangeAtItsBounds(t *testing.T) {
	for _, tc := range []struct {
		r    rune
		want bool
		what string
	}{
		{0x10ff, false, "below Hangul Jamo"},
		{0x1100, true, "Hangul Jamo, first"},
		{0x115f, true, "Hangul Jamo, last"},
		{0x1160, false, "past Hangul Jamo"},
		{0x2328, false, "below the bracket pair"},
		{0x2329, true, "left-pointing angle bracket"},
		{0x232a, true, "right-pointing angle bracket"},
		{0x232b, false, "past the bracket pair"},
		{0x2e7f, false, "below the CJK run"},
		{0x2e80, true, "CJK radicals, first"},
		{0x303f, false, "the ideographic half-fill space, carved out of the run"},
		{0x303e, true, "and its neighbour is not"},
		{0xa4cf, true, "CJK run, last"},
		{0xa4d0, false, "past the CJK run"},
		{0xabff, false, "below Hangul syllables"},
		{0xac00, true, "Hangul syllables, first"},
		{0xd7a3, true, "Hangul syllables, last"},
		{0xd7a4, false, "past Hangul syllables"},
		{0xf8ff, false, "below CJK compatibility ideographs"},
		{0xf900, true, "CJK compatibility ideographs, first"},
		{0xfaff, true, "CJK compatibility ideographs, last"},
		{0xfb00, false, "past them"},
		{0xfe2f, false, "below CJK compatibility forms"},
		{0xfe30, true, "CJK compatibility forms, first"},
		{0xfe6f, true, "CJK compatibility forms, last"},
		{0xfe70, false, "past them"},
		{0xfeff, false, "below the fullwidth forms"},
		{0xff00, true, "fullwidth forms, first"},
		{0xff60, true, "fullwidth forms, last"},
		{0xff61, false, "halfwidth forms are one column"},
		{0xffdf, false, "below the fullwidth signs"},
		{0xffe0, true, "fullwidth signs, first"},
		{0xffe6, true, "fullwidth signs, last"},
		{0xffe7, false, "past them"},
		{0x1f2ff, false, "below the emoji block"},
		{0x1f300, true, "emoji, first"},
		{0x1f64f, true, "emoji, last"},
		{0x1f650, false, "past the emoji block"},
		{0x1f8ff, false, "below the supplemental symbols"},
		{0x1f900, true, "supplemental symbols, first"},
		{0x1f9ff, true, "supplemental symbols, last"},
		{0x1fa00, false, "past them"},
		{0x1ffff, false, "below the CJK extension planes"},
		{0x20000, true, "CJK extension planes, first"},
		{0x3fffd, true, "CJK extension planes, last"},
		{0x3fffe, false, "past them"},
		{'a', false, "and an ordinary letter is one column"},
	} {
		if got := wide(tc.r); got != tc.want {
			t.Errorf("wide(%#x) = %v, want %v: %s", tc.r, got, tc.want, tc.what)
		}
	}
}
