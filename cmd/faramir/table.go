package main

// Column-aligned output that survives colour.
//
// text/tabwriter measures the bytes it is handed, so a painted cell widens its
// column by the length of the escape codes and every column after it slides.
// tabwriter.StripEscape removes the markers from the output but still measures
// what they bracket, so it does not help. These widths come from the visible
// text and the paint is applied afterwards, which is what logs.go does with its
// fixed widths; this is the same thing for widths that come from the data.

import (
	"fmt"
	"io"
	"strings"
)

// cell is one column of one row: the text a reader sees, and how to paint it.
// A nil paint leaves it alone, which is what a value the operator wrote gets.
type cell struct {
	text  string
	paint func(string) string
}

// value is a cell nothing paints: a path, a ref, a filename. Values keep their
// own colour so that faramir's words and the operator's stay told apart.
func value(text string) cell { return cell{text: text} }

// painted is a cell in faramir's own vocabulary: a header, a kind, a state.
func painted(text string, paint func(string) string) cell {
	return cell{text: text, paint: paint}
}

// printTable writes rows in aligned columns, two spaces between them, with no
// trailing space on the last column of a line.
func printTable(w io.Writer, rows [][]cell) {
	widths := make([]int, 0, 8)
	for _, row := range rows {
		for i, c := range row {
			for len(widths) <= i {
				widths = append(widths, 0)
			}
			if n := len([]rune(c.text)); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for _, row := range rows {
		var b strings.Builder
		for i, c := range row {
			text := c.text
			if c.paint != nil {
				text = c.paint(text)
			}
			b.WriteString(text)
			if i == len(row)-1 {
				break
			}
			b.WriteString(strings.Repeat(" ", widths[i]-len([]rune(c.text))+2))
		}
		_, _ = fmt.Fprintln(w, b.String())
	}
}
