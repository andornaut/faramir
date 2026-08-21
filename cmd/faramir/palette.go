package main

// Colour for the commands that print a report to a human. Off unless stdout is
// a terminal; $NO_COLOR is honoured whatever its value, per
// https://no-color.org, and --color=always overrides both. A character-device
// check rather than golang.org/x/term, which is only an indirect dependency.

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type palette struct {
	on bool
}

// addColorFlag registers --color on a command that prints a report to a human.
// Declared once rather than once per command: three commands paint, and the
// flag an operator types at one of them has to be the flag the others take.
// Not persistent on the root command, which would advertise it on `run`,
// `exec` and the daemons, where it decides nothing.
func addColorFlag(c *cobra.Command, when *string) {
	c.Flags().StringVar(when, "color", "auto", "colourise: auto, always or never")
}

func newPalette(when string) (palette, error) {
	switch when {
	case "always":
		return palette{on: true}, nil
	case "never":
		return palette{on: false}, nil
	case "auto", "":
		if _, set := os.LookupEnv("NO_COLOR"); set {
			return palette{on: false}, nil
		}
		return palette{on: isTerminal(os.Stdout)}, nil
	}
	return palette{}, fmt.Errorf("--color=%s: want auto, always or never", when)
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (p palette) wrap(code, text string) string {
	if !p.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (p palette) dim(text string) string  { return p.wrap("2", text) }
func (p palette) bold(text string) string { return p.wrap("1", text) }
func (p palette) ok(text string) string   { return p.wrap("32", text) }
func (p palette) bad(text string) string  { return p.wrap("31", text) }
func (p palette) warn(text string) string { return p.wrap("33", text) }
func (p palette) key(text string) string  { return p.wrap("36", text) }
func (p palette) ref(text string) string  { return p.wrap("35", text) }

// token highlights «SECRET:ref» in recorded output: where a credential was
// used, without being one.
func (p palette) token(text string) string {
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
