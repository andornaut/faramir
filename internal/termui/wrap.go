package termui

// Fitting prose to the terminal it is read on: how wide that is, whether it
// was told to expect UTF-8, and breaking a line to the width.

import (
	"os"
	"strconv"
	"strings"
)

// Wrap breaks text into lines that fit. Words only, so a path stays copyable:
// an over-long word overflows rather than being cut.
func Wrap(text string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	line := ""
	for word := range strings.FieldsSeq(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// Width is $COLUMNS, then 80. A wrong guess costs a wrapped line, so this
// needs no dependency.
func Width() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 40 {
		return columns
	}
	return 80
}

// UnicodeLocale reports whether the terminal was told to expect UTF-8, in the
// order the C library reads these.
func UnicodeLocale() bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(name); value != "" {
			return strings.Contains(strings.ToUpper(value), "UTF-8") ||
				strings.Contains(strings.ToUpper(value), "UTF8")
		}
	}
	return false
}
