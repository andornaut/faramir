package redact

// ANSI and control-character stripping: stage 1 of the pipeline documented on
// Package redact. A value the printing program spliced colour codes into is
// found against the stripped text, and the spans are mapped back onto the
// original.

import (
	"regexp"
	"strings"
)

var ansiRE = regexp.MustCompile(strings.Join([]string{
	"\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)",      // OSC ... BEL / ST
	"\x1b[P^_X][^\x1b]*\x1b\\\\",                // DCS / PM / APC / SOS
	"\x1b\\[[0-?]*[ -/]*[@-~]",                  // CSI
	"\x1b[()][B0UK]",                            // charset selection
	"\x1b[@-Z\\\\-_]",                           // two-character escapes
	"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]", // stray controls
}, "|"))

// How far back an incomplete escape sequence may reasonably start, in runes.
const maxEscapeLen = 64

// stripANSI removes escape sequences and normalises CRLF. Not stream-safe on
// its own; see stripANSIStream.
func stripANSI(text string) string {
	clean, _, _ := stripANSIViewSrc(text)
	return clean
}

// escapeView is the same text as the output stage 1 produced, with the last
// byte of every CSI sequence put back, plus what maps a match back onto that
// output.
//
// A CSI ends at the first byte in @-~, which is every letter and most
// punctuation, so a value written straight after an introducer that never got
// its own terminator supplies one: `ESC [` before "hunter2" is a sequence
// ending in "h", and what stage 2 then sees is "unter2", which matches nothing
// and goes out in the clear. Nothing in the bytes tells that apart from a real
// `ESC [ 3 2 h`, so the strip is right and the miss is stage 2 having only the
// stripped text to look at. Putting the byte back in a second haystack makes
// the value contiguous there either way: a real sequence leaves a stray letter
// in front of the value, which no match cares about.
//
// Only CSI. Every other sequence stage 1 removes ends on a byte a value cannot
// have supplied: OSC and DCS on BEL or ST, the two-character escapes on the
// byte the introducer already named, a stray control on itself.
type escapeView struct {
	view string
	// clean maps a byte offset in view to the offset in the stripped text where
	// that byte sits, a byte the strip removed mapping to the offset the next
	// surviving byte took. One entry per byte of view, plus one for the end.
	clean []int
	// lenient is false where no sequence gave a byte back, in which case view is
	// the stripped text and the plain pass covers everything this would find.
	lenient bool
}

// needsStrip reports whether stripping could change text: an ESC that may open
// a sequence, a CR that may open a CRLF, or one of the controls ansiRE removes
// on its own. Tab and newline are the two C0 controls that survive.
func needsStrip(text string) bool {
	for i := range len(text) {
		if b := text[i]; (b < 0x20 && b != '\t' && b != '\n') || b == 0x7f {
			return true
		}
	}
	return false
}

// stripANSIViewSrc removes escape sequences and normalises CRLF, and builds
// the view above in the same walk so the two cannot drift. src maps each byte
// of the stripped text back to the byte offset in text of the source byte that
// produced it, with one final entry mapping the end. A nil src means no
// stripping was needed and the stripped text is text itself, so the mapping is
// the identity.
//
// src is what lets the streaming redactor hold a chunk boundary back in the raw
// input rather than in the stripped text: a stripped offset it decides to emit
// up to is turned back into the raw offset to resume from, so the escape and
// CRLF context of the held tail is rebuilt from the raw on the next chunk
// instead of being lost when the escape is stripped away.
func stripANSIViewSrc(text string) (string, *escapeView, []int) {
	// Nothing to strip and nothing to normalise, which is most output: the walk
	// below would copy every byte twice to say so.
	if !needsStrip(text) {
		return text, nil, nil
	}
	var clean, view strings.Builder
	clean.Grow(len(text))
	view.Grow(len(text))
	index := make([]int, 0, len(text)+1)
	// One entry per byte of clean, plus one for the end. Reinserted view bytes
	// are not clean bytes and so are not recorded here.
	src := make([]int, 0, len(text)+1)
	ev := &escapeView{}
	// A CR is held until the next byte says whether it opened a CRLF. Held
	// across a sequence too, the sequence contributing nothing to the stripped
	// text: that is what makes this the same answer as stripping first and
	// normalising after. crAt is the raw offset of the held CR, for src.
	pendingCR := false
	crAt := 0
	put := func(chunk string, base int) {
		for i := range len(chunk) {
			b := chunk[i]
			if pendingCR {
				pendingCR = false
				if b != '\n' {
					index = append(index, clean.Len())
					src = append(src, crAt)
					clean.WriteByte('\r')
					view.WriteByte('\r')
				}
			}
			if b == '\r' {
				pendingCR = true
				crAt = base + i
				continue
			}
			index = append(index, clean.Len())
			src = append(src, base+i)
			clean.WriteByte(b)
			view.WriteByte(b)
		}
	}
	prev := 0
	for _, loc := range ansiRE.FindAllStringIndex(text, -1) {
		put(text[prev:loc[0]], prev)
		if seq := text[loc[0]:loc[1]]; strings.HasPrefix(seq, "\x1b[") {
			// At the offset the value's surviving bytes start from, so a match
			// covering this byte and the ones after it maps onto them alone.
			index = append(index, clean.Len())
			view.WriteByte(seq[len(seq)-1])
			ev.lenient = true
		}
		prev = loc[1]
	}
	put(text[prev:], prev)
	if pendingCR {
		index = append(index, clean.Len())
		src = append(src, crAt)
		clean.WriteByte('\r')
		view.WriteByte('\r')
	}
	index = append(index, clean.Len())
	src = append(src, len(text))
	ev.view, ev.clean = view.String(), index
	return clean.String(), ev, src
}
