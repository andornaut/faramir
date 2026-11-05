package redact

// The stream: what a chunk may emit now, and what is held back until the next
// one says whether a rendering continues into it.

import (
	"sort"
	"strings"
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
	complete, tail := SplitIncompleteTail(buf)
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

// SplitIncompleteTail splits buf into the leading bytes that decode to whole
// runes and a trailing remainder that begins a multibyte rune buf cut short. A
// lead byte whose sequence does not fit in buf is held; an outright invalid byte
// is left in complete so it is replaced now rather than held forever.
func SplitIncompleteTail(buf []byte) (complete, tail []byte) {
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
// already see, and never ends the emitted part inside or just after an escape
// sequence, inside one still open, or on the first half of a CRLF.
func (r *Redactor) settleBoundary() int {
	text := string(r.raw)
	clean, ev, src := stripANSIViewSrc(text)
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
	// The boundary is decided in the raw text from here on: a byte an escape
	// sequence took has no offset in clean, and it can belong to a value.
	cut := runeByte[holdRune]
	if src != nil {
		cut = src[cut]
	}
	spans := r.potentialSpans(clean, ev, src, runeByte)
	var seqs [][]int
	if ev != nil {
		seqs = ev.seqs
	}
	// Each rule below only moves the boundary earlier, so this ends.
	for {
		before := cut
		// Never cut a rendering the matcher can already see.
		for _, s := range spans {
			if s.start < cut && cut < s.end {
				cut = s.start
			}
		}
		// Not inside an escape sequence or just after one: the held part is
		// re-stripped with the next chunk, and a sequence it starts with is
		// rebuilt whole there.
		if i := sort.Search(len(seqs), func(i int) bool { return seqs[i][0] >= cut }); i > 0 && seqs[i-1][1] >= cut {
			cut = seqs[i-1][0]
		}
		// Not after a CR, which may be the first half of a CRLF the next chunk
		// closes, with nothing or only stray controls between: stage 1 removes
		// those before it pairs the CR.
		k := cut
		for k > 0 && strayControl(text[k-1]) {
			k--
		}
		if k > 0 && text[k-1] == '\r' {
			cut = k - 1
		}
		cut = holdOpenEscape(text, cut)
		if cut == before {
			break
		}
	}
	if cut <= 0 {
		return 0
	}
	return utf8.RuneCountInString(text[:cut])
}

// holdOpenEscape moves cut back to an escape sequence the text before it opens
// but does not close, if that starts within maxEscapeLen runes of cut. The next
// chunk may complete it, and stripping it now would emit its bytes as text
// where the whole sequence is meant to vanish:
//
//   - an ESC whose sequence has no terminator yet, such as `ESC [ 0 1 ;`
//   - an OSC, DCS, PM, APC or SOS with no BEL or ST yet, which on its own parses
//     as a two-character escape and leaves its body as text
//
// Further back than maxEscapeLen, a lone ESC is treated as text and an open
// OSC or DCS as a two-character escape followed by text, so the buffer never
// grows without bound waiting for a terminator that is not coming. A value in
// such a body is then matched as the text it is.
func holdOpenEscape(text string, cut int) int {
	lo := cut
	for k := 0; k < maxEscapeLen && lo > 0; k++ {
		_, size := utf8.DecodeLastRuneInString(text[:lo])
		lo -= size
	}
	esc := strings.LastIndexByte(text[lo:cut], 0x1b)
	if esc == -1 {
		return cut
	}
	esc += lo
	tail := text[esc:cut]
	loc := ansiRE.FindStringIndex(tail)
	if loc == nil || loc[0] != 0 {
		return esc
	}
	// A string sequence's introducer that matched only as a two-character
	// escape: its terminator is still to come.
	if loc[1] == 2 && strings.IndexByte("]PX^_", tail[1]) >= 0 {
		return esc
	}
	return cut
}

// potentialSpans returns, as byte ranges in the raw text, every rendering the
// three redact passes could match: plain, escape-view, and newline-collapsed.
// It is the boundary chooser's view of what must not be cut, so a superset is
// safe. src maps clean onto the raw text, nil meaning the two are the same.
func (r *Redactor) potentialSpans(clean string, ev *escapeView, src []int, runeByte []int) []span {
	if r.matcher == nil {
		return nil
	}
	toRaw := func(start, end int) span {
		if src == nil {
			return span{start: start, end: end}
		}
		return span{start: src[start], end: src[end-1] + 1}
	}
	var out []span
	for _, s := range r.matcher.find(clean) {
		out = append(out, toRaw(s.start, s.end))
	}
	if ev != nil {
		for _, loc := range r.matcher.find(ev.view) {
			out = append(out, span{start: ev.raw[loc.start], end: ev.raw[loc.end-1] + 1})
		}
	}
	if cv := newCollapsedView(clean); cv.collapsed {
		for _, loc := range r.matcher.find(cv.view) {
			startRune := cv.byteStart[loc.start]
			endRune := cv.byteStart[loc.end-1] + 1
			if startRune < len(runeByte) && endRune < len(runeByte) && startRune < endRune {
				out = append(out, toRaw(runeByte[startRune], runeByte[endRune]))
			}
		}
	}
	return out
}
