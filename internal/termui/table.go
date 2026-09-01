package termui

// Column-aligned output that survives colour.
//
// text/tabwriter measures the bytes it is handed, so a painted cell widens its
// column by the length of the escape codes and every column after it slides.
// tabwriter.StripEscape removes the markers from the output but still measures
// what they bracket, so it does not help. These widths come from how many
// columns a terminal spends on the text, counted after the text is escaped and
// before any paint is applied, which is what logs.go does with its fixed
// widths; this is the same thing for widths that come from the data.

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/andornaut/faramir/internal/termsafe"
)

// Cell is one column of one row: the text a reader sees, and how to paint it.
// A nil paint leaves it alone, which is what a value the operator wrote gets.
type Cell struct {
	text  string
	paint func(string) string
}

// Value is a cell nothing paints: a path, a ref, a filename. Values keep their
// own colour so that faramir's words and the operator's stay told apart.
func Value(text string) Cell { return Cell{text: text} }

// Painted is a cell in faramir's own vocabulary: a header, a kind, a state.
func Painted(text string, paint func(string) string) Cell {
	return Cell{text: text, paint: paint}
}

// Safe is one cell's text as it may be printed: escaped so a terminal draws it
// rather than acting on it, tabs included.
//
// The values in these tables are not faramir's own words. A path, a ref, a
// filename or a blocked entry is text somebody else chose, and a terminal obeys
// what it is sent: a bare carriage return returns the cursor so the rest of the
// row overwrites what came before it, and ESC c resets the terminal, which on
// many emulators takes the scrollback with it. So a row could read as an entry
// other than the one stored, which is the whole of what a listing is for.
// [internal/termsafe] holds the same rule for faramir logs and for an
// escalation prompt.
//
// Tab on top of what termsafe escapes: it is layout an operator wants in
// recorded output and is a column that moves in a table.
func Safe(text string) string {
	return strings.ReplaceAll(termsafe.Line(text), "\t", `\t`)
}

// Width is how many columns a terminal spends drawing this text. Not the rune
// count: a CJK ideograph and most emoji are drawn two columns wide, and a
// combining mark is drawn over the rune before it and takes none. Counting
// runes leaves every column after the widest of those out by the difference.
func Width(text string) int {
	n := 0
	for _, r := range text {
		switch {
		case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == 0x200d:
			// A combining mark or a zero-width joiner draws over what precedes it.
		case wide(r):
			n += 2
		default:
			n++
		}
	}
	return n
}

// wide is the East Asian Wide and Fullwidth ranges, plus the emoji blocks a
// terminal draws double. Enumerated here rather than taken from a dependency:
// this decides column alignment and nothing else, so being approximate at the
// edges costs a ragged column rather than a wrong answer.
func wide(r rune) bool {
	switch {
	case r < 0x1100:
		return false
	case r <= 0x115f, // Hangul Jamo
		r == 0x2329, r == 0x232a,
		r >= 0x2e80 && r <= 0xa4cf && r != 0x303f, // CJK, Kangxi, Hiragana, Katakana
		r >= 0xac00 && r <= 0xd7a3,                // Hangul syllables
		r >= 0xf900 && r <= 0xfaff,                // CJK compatibility ideographs
		r >= 0xfe30 && r <= 0xfe6f,                // CJK compatibility forms
		r >= 0xff00 && r <= 0xff60,                // fullwidth forms
		r >= 0xffe0 && r <= 0xffe6,
		r >= 0x1f300 && r <= 0x1f64f, // emoji
		r >= 0x1f900 && r <= 0x1f9ff,
		r >= 0x20000 && r <= 0x3fffd: // CJK extension planes
		return true
	}
	return false
}

// PrintTable writes rows in aligned columns, two spaces between them, with no
// trailing space on the last column of a line.
func PrintTable(w io.Writer, rows [][]Cell) {
	texts := make([][]string, len(rows))
	widths := make([]int, 0, 8)
	for r, row := range rows {
		texts[r] = make([]string, len(row))
		for i, c := range row {
			texts[r][i] = Safe(c.text)
			for len(widths) <= i {
				widths = append(widths, 0)
			}
			if n := Width(texts[r][i]); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for r, row := range rows {
		var b strings.Builder
		for i, c := range row {
			text := texts[r][i]
			pad := widths[i] - Width(text) + 2
			if c.paint != nil {
				text = c.paint(text)
			}
			b.WriteString(text)
			if i == len(row)-1 {
				break
			}
			b.WriteString(strings.Repeat(" ", pad))
		}
		_, _ = fmt.Fprintln(w, b.String())
	}
}
