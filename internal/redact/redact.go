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
//  4. This file is the redactor over the result. values.go builds the set of
//     renderings it searches for, and stream.go is the buffer that holds a
//     chunk back while a rendering split across two could still be arriving.
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
