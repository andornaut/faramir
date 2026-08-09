package main

// Colour for the commands that print a report to a human.
//
// Off unless stdout is a terminal, so a redirect, a pipe into grep and a
// systemd unit capturing output all get plain text.  $NO_COLOR is honoured
// whatever its value, per https://no-color.org, and --color=always overrides
// both for the case of piping into a pager that renders escapes.
//
// No dependency for this.  golang.org/x/term is in the module graph only
// indirectly, and a character-device check answers the same question without
// promoting it: the point of the port was a static binary that links little.

import (
	"fmt"
	"os"
	"strings"
)

type palette struct {
	on bool
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
func (p palette) key(text string) string  { return p.wrap("36", text) }
func (p palette) ref(text string) string  { return p.wrap("35", text) }

// token highlights «SECRET:ref» where it appears in recorded output, which is
// the thing a reader is looking for: it marks where a credential was used
// without being a credential.
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
