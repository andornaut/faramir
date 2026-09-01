// Package termui draws what the commands that report to a human print: colour,
// and columns that stay aligned under it.
//
// Colour is off unless stdout is a terminal; $NO_COLOR is honoured whatever its
// value, per https://no-color.org, and --color=always overrides both. A
// character-device check rather than golang.org/x/term, which is only an
// indirect dependency.
//
// Every value that reaches a table is escaped before it is measured or painted.
// The values in these listings are not faramir's own words -- a path, a ref, a
// filename -- and a terminal obeys what it is sent, so a row could otherwise
// read as an entry other than the one stored.
package termui

import (
	"fmt"
	"os"
	"strings"
)

type Palette struct {
	on bool
}

// PaletteFor resolves --color for one command, printing a refusal under that
// command's own name. A non-zero second return is the usage status to exit
// with.
func PaletteFor(label, when string) (Palette, int) {
	paint, err := NewPalette(when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return paint, 2
	}
	return paint, 0
}

func NewPalette(when string) (Palette, error) {
	switch when {
	case "always":
		return Palette{on: true}, nil
	case "never":
		return Palette{on: false}, nil
	case "auto", "":
		if _, set := os.LookupEnv("NO_COLOR"); set {
			return Palette{on: false}, nil
		}
		return Palette{on: IsTerminal(os.Stdout)}, nil
	}
	return Palette{}, fmt.Errorf("--color=%s: want auto, always or never", when)
}

func IsTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// On reports whether this palette paints. For a caller that has to know
// whether colour was resolved on rather than what one word came out looking
// like.
func (p Palette) On() bool { return p.on }

func (p Palette) wrap(code, text string) string {
	if !p.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (p Palette) Dim(text string) string  { return p.wrap("2", text) }
func (p Palette) Bold(text string) string { return p.wrap("1", text) }
func (p Palette) OK(text string) string   { return p.wrap("32", text) }
func (p Palette) Bad(text string) string  { return p.wrap("31", text) }
func (p Palette) Warn(text string) string { return p.wrap("33", text) }
func (p Palette) Key(text string) string  { return p.wrap("36", text) }
func (p Palette) Ref(text string) string  { return p.wrap("35", text) }

// Token highlights «SECRET:ref» in recorded output: where a credential was
// used, without being one.
func (p Palette) Token(text string) string {
	if !p.on {
		return text
	}
	var out []byte
	for {
		start := strings.Index(text, "«SECRET:")
		if start < 0 {
			return string(append(out, text...))
		}
		end := strings.Index(text[start:], "»")
		if end < 0 {
			return string(append(out, text...))
		}
		end += start + len("»")
		out = append(out, text[:start]...)
		out = append(out, p.wrap("35", text[start:end])...)
		text = text[end:]
	}
}
