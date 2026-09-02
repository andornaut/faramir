package redact

// The stream: what a chunk may emit now, and what is held back until the next
// one says whether a rendering continues into it.

import (
	"unicode/utf8"
)

// holdCapRunes bounds how much raw input the stream holds back waiting for the
// non-newline overlap window to fill, so blank-line padding between a
// rendering's characters cannot grow the buffer without limit. A rendering
// spread across more than this many runes of padding is emitted rather than
// held, and so is not caught once wrapped: 1 MiB is far above any real
// formatter's line spacing and below anything that pressures memory.
const holdCapRunes = 1 << 20

// Feed absorbs a chunk of raw output and returns the part that is safe to emit.
func (r *Redactor) Feed(text string) string {
	if text == "" {
		return ""
	}
	// Reattach any bytes held from the previous chunk, then split off a new
	// incomplete tail if this chunk ends mid-rune, so a multibyte rune spanning
	// the boundary is decoded whole.
	buf := make([]byte, 0, len(r.rawBytes)+len(text))
	buf = append(buf, r.rawBytes...)
	buf = append(buf, text...)
	r.rawBytes = nil
	complete, tail := splitIncompleteTail(buf)
	r.rawBytes = tail
	if len(complete) == 0 {
		return ""
	}
	settled := string(complete)
	// Counted before the conversion below, which replaces an invalid byte and so
	// is the last moment one can be told from a U+FFFD the command wrote.
	// Callers report the count rather than act on it. The new bytes only: the
	// held raw was counted when it first arrived, and the incomplete tail is
	// counted when it is completed or flushed, not now.
	r.invalidBytes += invalidUTF8Bytes(settled)
	r.raw = append(r.raw, []rune(settled)...)
	return r.process(false)
}

// Flush releases everything held back. Call once, at end of stream.
func (r *Redactor) Flush() string {
	// A trailing byte still held at end of stream was a genuinely incomplete
	// rune, not a split one: emit it so the output is not truncated, counting it
	// as the invalid byte it turned out to be.
	if len(r.rawBytes) > 0 {
		settled := string(r.rawBytes)
		r.invalidBytes += invalidUTF8Bytes(settled)
		r.raw = append(r.raw, []rune(settled)...)
		r.rawBytes = nil
	}
	out := r.process(true)
	r.raw = nil
	return out
}

// splitIncompleteTail splits buf into the leading bytes that decode to whole
// runes and a trailing remainder that begins a multibyte rune buf cut short. A
// lead byte whose sequence does not fit in buf is held; an outright invalid byte
// is left in complete so it is replaced now rather than held forever.
func splitIncompleteTail(buf []byte) (complete, tail []byte) {
	for i := len(buf) - 1; i >= 0 && i >= len(buf)-utf8.UTFMax; i-- {
		b := buf[i]
		if b < utf8.RuneSelf {
			break // ASCII: everything from here on is whole.
		}
		if utf8.RuneStart(b) {
			if need := leadRuneLen(b); need > len(buf)-i {
				return buf[:i], buf[i:]
			}
			break
		}
		// A continuation byte: keep scanning left for its lead byte.
	}
	return buf, nil
}

// leadRuneLen is the byte length of the rune a UTF-8 lead byte begins, or 1 for
// a byte that is not a valid lead so it is treated as one invalid byte.
func leadRuneLen(b byte) int {
	switch {
	case b&0xE0 == 0xC0:
		return 2
	case b&0xF0 == 0xE0:
		return 3
	case b&0xF8 == 0xF0:
		return 4
	default:
		return 1
	}
}

// process strips and redacts the settled prefix of r.raw and returns it, holding
// the rest back in r.raw for the next chunk. When final is true it emits
// everything. A match found in the emitted prefix is counted once here; the held
// tail is reprocessed on the next chunk, and its matches are counted when they
// in turn become part of an emitted prefix, so nothing is counted twice.
func (r *Redactor) process(final bool) string {
	if len(r.raw) == 0 {
		return ""
	}
	settled := r.raw
	if final {
		r.raw = nil
	} else {
		cut := r.settleBoundary()
		if cut == 0 {
			return ""
		}
		settled = r.raw[:cut]
		r.raw = append([]rune(nil), r.raw[cut:]...)
	}
	clean, ev, _ := stripANSIViewSrc(string(settled))
	return r.redact(clean, ev)
}

// settleBoundary returns the rune index in r.raw up to which it is safe to strip
// and emit now, holding the rest back so a value, an escape, or a CRLF split
// across the next chunk is still caught. It holds back at least Overlap
// non-newline runes of stripped output, never cuts a rendering the matcher can
// already see, and never ends the emitted part inside an escape sequence or on
// the first half of a CRLF.
func (r *Redactor) settleBoundary() int {
	clean, ev, src := stripANSIViewSrc(string(r.raw))
	cleanRunes := []rune(clean)
	n := len(cleanRunes)
	// runeByte[k] is the byte offset in clean of clean rune k, plus the end.
	runeByte := make([]int, n+1)
	off := 0
	for k, ch := range cleanRunes {
		runeByte[k] = off
		off += utf8.RuneLen(ch)
	}
	runeByte[n] = len(clean)

	// Hold back Overlap non-newline runes, so a rendering wrapped across any
	// number of blank lines is held until all of its own characters have come in.
	held := 0
	holdRune := 0
	for k := n - 1; k >= 0; k-- {
		if cleanRunes[k] != '\n' && cleanRunes[k] != '\r' {
			held++
			if held >= r.Overlap {
				holdRune = k
				break
			}
		}
	}
	// The cap bounds memory when the non-newline budget is never met, e.g. a flood
	// of blank lines whose non-newline count never reaches Overlap. A rendering
	// padded past the cap is emitted rather than held, and so is not caught once
	// wrapped.
	if n-holdRune > holdCapRunes {
		holdRune = n - holdCapRunes
	}
	if holdRune <= 0 {
		return 0
	}
	bb := runeByte[holdRune]

	// Never cut a rendering the matcher can already see: pull the boundary back to
	// the start of any match that would straddle it. Bounded: a match is at most
	// the longest rendering, and each pull moves the boundary strictly earlier.
	spans := r.potentialSpans(clean, ev, runeByte)
	for moved := true; moved; {
		moved = false
		for _, s := range spans {
			if s.start < bb && bb < s.end {
				bb = s.start
				moved = true
			}
		}
	}
	if bb <= 0 {
		return 0
	}

	// bb is a byte offset in clean at a rune boundary; src turns it into the raw
	// byte offset to resume from. A nil src means no stripping, so clean is the
	// raw and the offsets are the same.
	rawByte := bb
	if src != nil {
		rawByte = src[bb]
	}
	cut := utf8.RuneCountInString(string(r.raw)[:rawByte])

	// Do not end the emitted part inside an escape sequence or on a lone CR: a
	// stripped escape contributes no clean byte, so the boundary can land just
	// after one whose reinserted byte belongs to a value that continues in the
	// held part, and a CR may be the first half of a CRLF the next chunk closes.
	// Pull the boundary back over either so the raw is rebuilt with the rest.
	for cut > 0 {
		if r.raw[cut-1] == '\r' {
			cut--
			continue
		}
		lo := max(cut-maxEscapeLen, 0)
		window := string(r.raw[lo:cut])
		pulled := false
		for _, loc := range ansiRE.FindAllStringIndex(window, -1) {
			if loc[1] == len(window) {
				cut = lo + utf8.RuneCountInString(window[:loc[0]])
				pulled = true
				break
			}
		}
		if !pulled {
			break
		}
	}

	// Also hold back an escape the settled part opens but does not close: an ESC
	// within maxEscapeLen of the boundary whose sequence has no terminator yet is
	// completed by the next chunk, and stripping it now would emit its parameter
	// bytes as text where the whole sequence is meant to vanish. Beyond
	// maxEscapeLen a lone ESC is treated as text, so a buffer never grows without
	// bound waiting for a terminator that is not coming.
	for cut > 0 {
		lo := max(cut-maxEscapeLen, 0)
		esc := -1
		for i := cut - 1; i >= lo; i-- {
			if r.raw[i] == '\x1b' {
				esc = i
				break
			}
		}
		if esc == -1 {
			break
		}
		tail := string(r.raw[esc:cut])
		if loc := ansiRE.FindStringIndex(tail); loc != nil && loc[0] == 0 {
			break // a complete sequence begins at esc; the settled part may keep it
		}
		cut = esc
	}
	return cut
}

// potentialSpans returns, as byte ranges in clean, every rendering the three
// redact passes could match: plain, escape-view, and newline-collapsed. It is
// the boundary chooser's view of what must not be cut, so a superset is safe.
func (r *Redactor) potentialSpans(clean string, ev *escapeView, runeByte []int) []span {
	if r.matcher == nil {
		return nil
	}
	out := append([]span(nil), r.matcher.find(clean)...)
	if ev != nil && ev.lenient {
		for _, loc := range r.matcher.find(ev.view) {
			start, end := ev.clean[loc.start], ev.clean[loc.end]
			if end > start {
				out = append(out, span{start: start, end: end})
			}
		}
	}
	if cv := newCollapsedView(clean); cv.collapsed {
		for _, loc := range r.matcher.find(cv.view) {
			startRune := cv.byteStart[loc.start]
			endRune := cv.byteStart[loc.end-1] + 1
			if startRune < len(runeByte) && endRune < len(runeByte) {
				out = append(out, span{start: runeByte[startRune], end: runeByte[endRune]})
			}
		}
	}
	return out
}
