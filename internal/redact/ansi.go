package redact

// ANSI and control-character stripping: stage 1 of the pipeline documented on
// Package redact. A value the printing program spliced colour codes into is
// found against the stripped text, and the spans are mapped back onto the
// original.

import (
	"regexp"
	"sort"
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
// The stream holds back a sequence that has not ended yet only while it starts
// within this distance of where it would otherwise cut; see settleBoundary.
const maxEscapeLen = 64

// stripANSI removes escape sequences and normalises CRLF. Not stream-safe on
// its own; see stripANSIViewSrc.
func stripANSI(text string) string {
	clean, _, _ := stripANSIViewSrc(text)
	return clean
}

// escapeView is a second haystack beside the stripped text: the input with ESC
// and the stray controls taken out, every other byte of every escape sequence
// kept, and CRLF normalised. A value an escape sequence took bytes of is
// contiguous here.
//
// Stage 1 strips a sequence whole, and nothing in the bytes says whether the
// program meant a byte as part of a sequence or as text, so a value written
// straight after an introducer that never got its own terminator becomes part
// of the sequence:
//
//	written after               what the sequence takes of the value
//	ESC                         the first byte, if in @-Z or \-_ (a capital letter)
//	ESC [, with any parameters  the first byte, if in @-~ (every letter)
//	ESC ( or ESC )              the first byte, if it is B, 0, U or K
//	ESC ] (OSC)                 all of it, when the next BEL or ESC is a BEL or an ST
//	ESC P, ESC X, ESC ^, ESC _  all of it, when the next ESC is an ST
//
// The strip is right either way, and the miss is stage 2 having only the
// stripped text to look at. In this view a real sequence leaves its own bytes
// in front of or around the value, which no match cares about. A value whose
// every byte a sequence took is matched with nothing left of it in the stripped
// text, and its token stands where the sequence stood.
type escapeView struct {
	view string
	// raw maps a byte offset in view to the input offset of the byte it came
	// from, plus one entry for the end.
	raw []int
	// src is the stripped text's map onto the input, from stripANSIViewSrc.
	src []int
	// seqs are the input spans of the escape sequences stage 1 removed, in
	// order. The stray controls are not among them: one is a single byte and
	// takes nothing from a value.
	seqs [][]int
}

// cleanSpan maps a match in view onto the stripped text: the span there that
// holds what the sequences left of the matched bytes, empty where they left
// nothing.
func (v *escapeView) cleanSpan(loc span) (start, end int) {
	return sort.SearchInts(v.src, v.raw[loc.start]), sort.SearchInts(v.src, v.raw[loc.end-1]+1)
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

// strayControl reports whether b is a control stage 1 removes wherever it
// stands: the C0 set and DEL, less ESC, tab, newline and CR.
func strayControl(b byte) bool {
	return (b < 0x20 && b != 0x1b && b != '\t' && b != '\n' && b != '\r') || b == 0x7f
}

// crlfWriter writes bytes with CRLF normalised to LF, recording for each byte
// written the input offset it came from.
type crlfWriter struct {
	b  strings.Builder
	at []int
	// A CR is held until the next byte says whether it opened a CRLF. crAt is
	// its input offset.
	cr   bool
	crAt int
}

func newCRLFWriter(n int) *crlfWriter {
	w := &crlfWriter{at: make([]int, 0, n+1)}
	w.b.Grow(n)
	return w
}

func (w *crlfWriter) put(b byte, at int) {
	if w.cr {
		w.cr = false
		if b != '\n' {
			w.at = append(w.at, w.crAt)
			w.b.WriteByte('\r')
		}
	}
	if b == '\r' {
		w.cr = true
		w.crAt = at
		return
	}
	w.at = append(w.at, at)
	w.b.WriteByte(b)
}

// end releases a held CR and records the end offset n.
func (w *crlfWriter) end(n int) (string, []int) {
	if w.cr {
		w.at = append(w.at, w.crAt)
		w.b.WriteByte('\r')
	}
	w.at = append(w.at, n)
	return w.b.String(), w.at
}

// stripANSIViewSrc removes escape sequences and normalises CRLF, and builds
// the view above in the same walk so the two cannot drift. src maps each byte
// of the stripped text back to the byte offset in text of the source byte that
// produced it, with one final entry mapping the end. A nil src means no
// stripping was needed and the stripped text is text itself, so the mapping is
// the identity. A nil view means no escape sequence was removed, so the
// stripped text holds every byte the view would.
//
// src is what lets the streaming redactor hold a chunk boundary back in the raw
// input rather than in the stripped text: a stripped offset it decides to emit
// up to is turned back into the raw offset to resume from, so the escape and
// CRLF context of the held tail is rebuilt from the raw on the next chunk
// instead of being lost when the escape is stripped away.
func stripANSIViewSrc(text string) (string, *escapeView, []int) {
	// Nothing to strip and nothing to normalise, which is most output: the walk
	// below would copy every byte to say so.
	if !needsStrip(text) {
		return text, nil, nil
	}
	locs := ansiRE.FindAllStringIndex(text, -1)
	// The view is built only when an escape sequence is removed. CRLF and stray
	// controls alone, which is what a PTY delivers, leave nothing for it to find.
	var view *crlfWriter
	for _, loc := range locs {
		if text[loc[0]] == 0x1b {
			view = newCRLFWriter(len(text))
			break
		}
	}
	// A CR is held across a sequence, the sequence contributing nothing to the
	// stripped text: that is what makes this the same answer as stripping first
	// and normalising after. The view holds its own CR, since a sequence does
	// contribute to it.
	clean := newCRLFWriter(len(text))
	var seqs [][]int
	prev := 0
	for _, loc := range locs {
		for i := prev; i < loc[0]; i++ {
			clean.put(text[i], i)
			if view != nil {
				view.put(text[i], i)
			}
		}
		if view != nil && text[loc[0]] == 0x1b {
			seqs = append(seqs, loc)
			for i := loc[0] + 1; i < loc[1]; i++ {
				if b := text[i]; b != 0x1b && !strayControl(b) {
					view.put(b, i)
				}
			}
		}
		prev = loc[1]
	}
	for i := prev; i < len(text); i++ {
		clean.put(text[i], i)
		if view != nil {
			view.put(text[i], i)
		}
	}
	out, src := clean.end(len(text))
	if view == nil {
		return out, nil, src
	}
	ev := &escapeView{src: src, seqs: seqs}
	ev.view, ev.raw = view.end(len(text))
	return out, ev, src
}
