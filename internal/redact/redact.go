// Package redact provides streaming, encoding-aware redaction of secret values.
// See docs/redaction.md.
//
// It works on a stream, output arriving in arbitrary chunks, and has to catch a
// value the printing program mangled on the way out: colour codes spliced in,
// base64 line wrapping, URL escaping, shell quoting.
//
// Everything index-sensitive works on []rune, a byte-offset slice being able to
// cut a multi-byte character in half.
//
// Four stages, a file each, and each exists for a case the stage itself does
// not make obvious:
//
//  1. ansi.go strips ANSI and the control characters, and maps what is found in
//     the stripped text back onto the original.
//  2. variants.go expands one value into every spelling it leaves a program in:
//     base64, base32, percent, shell quoting, JSON escaping.
//  3. eligibility.go refuses a value too short to search for, which would match
//     inside ordinary words and blank unrelated output.
//  4. This file is the streaming redactor over the result.
package redact

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// rendering is one spelling of one value, and the token it stands for.
type rendering struct {
	text  string
	token string
}

// Count is one row of the wire response's "redactions" field.
type Count struct {
	Token string `json:"token"`
	Count int    `json:"count"`
}

// Values is the compiled value set: every rendering of every secret, and what
// each stands for. Immutable once built and safe to share, which is the point
// of it being separate from Redactor.
//
// Building one is the expensive half -- every rendering of every value, and the
// automaton over them -- and the set changes only when the store reloads, where
// a redactor is per request. Sharing the build is worth the split: the broker
// makes four redactors for one `run` and five for one `redact` stream, and
// rebuilding the set in each made a command that produced no output at all cost
// 35 ms on a host with 256 refs.
type Values struct {
	Policy EligibilityPolicy
	// Overlap is the tail a stream holds back, in non-newline runes, a property of
	// the longest rendering rather than of one request.
	Overlap int
	// One automaton over every rendering of every value, rather than one search
	// per value: the scan is the cost paid on every byte of every command's
	// output, and a search per value made it the number of refs times the size of
	// the output.
	matcher *matcher
	// The token a matched rendering stands for. A match is a string the automaton
	// was built from, so this is a lookup rather than a search.
	tokenOf map[string]string
}

// Redactor replaces every known secret rendering with a stable token. Feed
// withholds a tail so a value split across two reads is still caught; Flush
// releases it.
//
// One per request: it carries the counts and the stream's own buffers. The set
// it matches against is shared.
type Redactor struct {
	*Values

	counts map[string]int
	// raw is the input held back for the next chunk: an incomplete escape or CRLF
	// half at the very end, and the overlap window that a value split across the
	// boundary is caught in. Held raw rather than stripped, so an escape that ate
	// a value's first byte is re-stripped with the rest of the value on the next
	// chunk instead of leaving its stripped remainder to go out in the clear.
	raw []rune
	// rawBytes holds a chunk's trailing bytes when they begin a multibyte rune
	// the chunk cut short, so the rune is decoded whole once its rest arrives
	// rather than corrupted to U+FFFD on each side of the split. Prepended to the
	// next chunk; flushed as-is at end of stream.
	rawBytes []byte
	// Bytes that were not valid UTF-8, counted rather than acted on; see Feed.
	invalidBytes int
}

// Secret is one (ref, value) pair fed to the redactor.
type Secret struct {
	Ref   string
	Value string
}

// New builds a redactor over the given secrets. A value the policy refuses is
// not matched; naming it is the secretstore package's job.
//
// A caller that redacts more than once against the same set should build the
// set with NewValues and take a Redactor per request from it.
func New(secrets []Secret, policy EligibilityPolicy) *Redactor {
	return NewValues(secrets, policy).Redactor()
}

// Redactor is one request's redactor over this set. Cheap: the automaton and
// the token table are shared, and only the counts and the stream buffers are
// this one's.
func (v *Values) Redactor() *Redactor {
	return &Redactor{Values: v, counts: map[string]int{}}
}

// NewValues compiles the set. A value the policy refuses is not matched; naming
// it is the secretstore package's job.
func NewValues(secrets []Secret, policy EligibilityPolicy) *Values {
	r := &Values{Policy: policy, tokenOf: map[string]string{}}
	seen := map[string]bool{}
	var kept []Secret
	for _, s := range secrets {
		if seen[s.Value] || policy.Check(s.Value) != "" {
			continue
		}
		seen[s.Value] = true
		kept = append(kept, s)
	}
	// Longest value first, so where two values render the same string the one
	// that contains the other owns it.
	sort.SliceStable(kept, func(i, j int) bool {
		return len([]rune(kept[i].Value)) > len([]rune(kept[j].Value))
	})

	var all []rendering
	longest := 0
	for _, s := range kept {
		token := TokenFor(s.Ref)
		for _, text := range renderings(s.Value, policy) {
			if _, taken := r.tokenOf[text]; taken {
				continue
			}
			r.tokenOf[text] = token
			all = append(all, rendering{text: text, token: token})
			if n := len([]rune(text)); n > longest {
				longest = n
			}
		}
	}
	if len(all) > 0 {
		r.matcher = newMatcher(all)
	}
	// The overlap window is measured in non-newline runes, so a rendering wrapped
	// across any number of lines is held until all of its own characters have
	// arrived regardless of the blank lines between them. longest bounds a
	// rendering's own length; the rest is slack for a reinserted escape byte and
	// for quoting expansion at a chunk boundary.
	r.Overlap = longest + 16
	return r
}

// renderings is every spelling of one value the matcher recognises, sorted so
// the set is the same on every process.
//
// Stage 1 rewrites the text before any of this is matched against it, so the
// value as stage 1 would leave it is a rendering of its own: a value carrying a
// CRLF, a C0 control or an escape sequence never appears in the output the way
// it appears in the store, and a pattern built only from the store's spelling
// would not meet it. Added only where it is still long enough to search for,
// a value that is mostly control characters collapsing to something that would
// eat the output.
func renderings(value string, policy EligibilityPolicy) []string {
	set := variants(value)
	if stripped := stripANSI(value); stripped != value && policy.Check(stripped) == "" {
		for v := range variants(stripped) {
			set[v] = true
		}
	}
	for v := range acrossLines(value, policy) {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// lineSeparators is what an ordinary rendering puts where a value's newline was.
// A shell that expands a value unquoted word-splits it and joins the fields with
// a space; a formatter re-wraps with CRLF or a tab. Nothing here is an attempt
// to defeat redaction, which is why these are matched rather than accepted.
var lineSeparators = []string{" ", "\t", "\r\n", "\r", "\n\n"}

// acrossLines returns the spellings a value spanning lines needs beyond its own.
//
// The whole-value renderings match only while the lines stay adjacent, and
// ordinary tools do not keep them adjacent. `cat -n`, `nl` and `grep -n` put a
// line number between them, `sed -n 2p` prints one line and never the other, and
// an unquoted expansion joins them with a space. Against a single literal
// spelling every one of those emits the value in the clear, and the redaction
// count reports nothing missed, because nothing matched.
//
// Two additions, which is what those routes leave to match against:
//
//   - Each line on its own. Every route above emits the individual lines whole,
//     whatever it puts between them, so a per-line needle meets all of them.
//   - The whole value with its newlines rewritten to the other separators a
//     shell or a formatter substitutes. Redundant with the per-line needles for
//     most values, and the only cover for one whose lines are each too short to
//     register.
//
// A line the policy refuses is not added, so a value can end up partly covered.
// That is the same rule a short single-line value meets, and secretstore is what
// names a value it will not redact.
func acrossLines(value string, policy EligibilityPolicy) map[string]bool {
	out := map[string]bool{}
	if !strings.ContainsAny(value, "\n\r") {
		return out
	}
	norm := strings.ReplaceAll(value, "\r\n", "\n")
	for line := range strings.SplitSeq(norm, "\n") {
		if line == "" || policy.Check(line) != "" {
			continue
		}
		for v := range variants(line) {
			out[v] = true
		}
	}
	for _, sep := range lineSeparators {
		joined := strings.ReplaceAll(norm, "\n", sep)
		if joined == value || policy.Check(joined) != "" {
			continue
		}
		for v := range variants(joined) {
			out[v] = true
		}
	}
	delete(out, "")
	return out
}

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

// RedactText is a one-shot convenience for text that is already complete.
func (r *Redactor) RedactText(text string) string { return r.Feed(text) + r.Flush() }

// InvalidBytes is how many bytes of everything fed in were not valid UTF-8.
// Non-zero means the output was not text and what came back is not what the
// command wrote: an invalid byte becomes U+FFFD, and the C0 controls that fill
// binary are stripped outright. A caller that pipes the output somewhere
// reports this, so a corrupted archive is visible when it is produced.
func (r *Redactor) InvalidBytes() int { return r.invalidBytes }

// invalidUTF8Bytes counts the bytes in text that do not begin a valid rune.
func invalidUTF8Bytes(text string) int {
	n := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			n++
		}
		i += size
	}
	return n
}

// Summary is the wire response's "redactions": tokens and counts, never values.
func (r *Redactor) Summary() []Count {
	out := []Count{}
	for token, count := range r.counts {
		if count > 0 {
			out = append(out, Count{Token: token, Count: count})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// tokenSpan is a match to replace: the offsets it covers and the token it
// stands for. The offsets are into whatever source the splice reads, byte or
// rune, so long as size and between below share that index space.
type tokenSpan struct {
	start, end int
	token      string
}

// spliceSpans writes source with each span replaced by its token. size is the
// source length in the spans' index space, and between returns source[a:b] in
// it. A span that starts inside the previous one covers only its uncovered tail,
// and one wholly covered is skipped, so partially overlapping secrets are both
// redacted without a negative slice.
func (r *Redactor) spliceSpans(spans []tokenSpan, size int, between func(a, b int) string) string {
	var b strings.Builder
	b.Grow(size)
	cursor := 0
	for _, s := range spans {
		if s.end <= cursor {
			continue
		}
		if s.start < cursor {
			b.WriteString(s.token)
		} else {
			b.WriteString(between(cursor, s.start))
			b.WriteString(s.token)
		}
		r.counts[s.token]++
		cursor = s.end
	}
	b.WriteString(between(cursor, size))
	return b.String()
}

func (r *Redactor) redact(text string, ev *escapeView) string {
	if text == "" || r.matcher == nil {
		return text
	}
	// The escape pass first, against a view holding the byte a CSI took from the
	// front of a value. Only what that view alone can find: everything still
	// contiguous in text is left to the two passes below, so the ordinary case
	// pays nothing here and this one is not scanned twice.
	if out, changed := r.subEscaped(text, ev); changed {
		text = out
	}
	// The wrapped pass next, against a newline-free view of the output, so it
	// catches a rendering a formatter split across lines: base64 wraps at 76
	// columns, and `fold` wraps every rendering the same way. The newline guard
	// in subWrapped keeps it to genuinely line-spanning matches, so the plain
	// pass below still owns everything on a single line.
	//
	// Newlines only: a continuation the formatter indents still has whitespace
	// between the fragments and is not caught. Collapsing the indentation too
	// would join any two words straddling an indented line break, which corrupts
	// more output than the wrapping it would catch.
	if out, changed := r.subWrapped(newCollapsedView(text)); changed {
		text = out
	}
	// One pass, whatever the number of values: the automaton carries every
	// rendering and the match says which value it was.
	spans := r.matcher.find(text)
	if len(spans) == 0 {
		// Nothing built and nothing copied, which is the ordinary case: most output
		// carries no secret at all.
		return text
	}
	toks := make([]tokenSpan, 0, len(spans))
	for _, s := range spans {
		token, ok := r.tokenOf[text[s.start:s.end]]
		if !ok {
			continue // unreachable: the automaton is built from these keys
		}
		toks = append(toks, tokenSpan{start: s.start, end: s.end, token: token})
	}
	return r.spliceSpans(toks, len(text), func(a, b int) string { return text[a:b] })
}

// collapsedView is one haystack with its line breaks taken out, plus what maps
// a match back onto the original: a formatter can wrap a value across lines, so
// matching happens against view and the replaced span is in the original.
type collapsedView struct {
	// runes is the original, indexed the way the spans below are.
	runes []rune
	view  string
	// byteStart maps a byte offset in view to the index in runes of the rune
	// beginning there, plus one entry for the end.
	byteStart []int
	// collapsed is false when there were no line breaks, in which case the plain
	// pass covers everything this would find.
	collapsed bool
}

func newCollapsedView(text string) *collapsedView {
	v := &collapsedView{}
	if !strings.ContainsAny(text, "\n\r") {
		return v
	}
	v.collapsed = true
	v.runes = []rune(text)
	var b strings.Builder
	b.Grow(len(text))
	v.byteStart = make([]int, 0, len(text)+1)
	for i, ch := range v.runes {
		if ch == '\n' || ch == '\r' {
			continue
		}
		for range utf8.RuneLen(ch) {
			v.byteStart = append(v.byteStart, i)
		}
		b.WriteRune(ch)
	}
	v.byteStart = append(v.byteStart, len(v.runes))
	v.view = b.String()
	return v
}

// subEscaped replaces every value that is whole only in the escape view, and
// reports whether it changed anything. The span it replaces is in text: the
// byte the sequence took is not there, so the token stands where what survived
// of the value stood.
func (r *Redactor) subEscaped(text string, v *escapeView) (string, bool) {
	if v == nil || !v.lenient {
		return "", false
	}
	var spans []tokenSpan
	for _, loc := range r.matcher.find(v.view) {
		token, ok := r.tokenOf[v.view[loc.start:loc.end]]
		if !ok {
			continue // unreachable: the automaton is built from these keys
		}
		start, end := v.clean[loc.start], v.clean[loc.end]
		// Only a match a returned byte made whole. One the same length in both is
		// contiguous in text as well, and the plain pass owns it: taking it here
		// would count it and then leave that pass nothing, which reads the same
		// but pays for two scans of every value.
		if end-start == loc.end-loc.start || end <= start {
			continue
		}
		spans = append(spans, tokenSpan{start: start, end: end, token: token})
	}
	if len(spans) == 0 {
		return "", false
	}
	return r.spliceSpans(spans, len(text), func(a, b int) string { return text[a:b] }), true
}

// subWrapped replaces every line-wrapped rendering, and reports whether it
// changed anything. Its spans are offsets into the original runes, so the splice
// reads v.runes rather than a byte string.
func (r *Redactor) subWrapped(v *collapsedView) (string, bool) {
	if !v.collapsed {
		return "", false
	}
	var spans []tokenSpan
	for _, loc := range r.matcher.find(v.view) {
		token, ok := r.tokenOf[v.view[loc.start:loc.end]]
		if !ok {
			continue // unreachable: the automaton is built from these keys
		}
		// byteStart is indexed by byte, so the end comes from the match's last byte
		// rather than the offset after it.
		start, end := v.byteStart[loc.start], v.byteStart[loc.end-1]+1
		if strings.ContainsAny(string(v.runes[start:end]), "\n\r") {
			spans = append(spans, tokenSpan{start: start, end: end, token: token})
		}
	}
	if len(spans) == 0 {
		return "", false
	}
	return r.spliceSpans(spans, len(v.runes), func(a, b int) string {
		return string(v.runes[a:b])
	}), true
}
