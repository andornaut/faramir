// Package redact provides streaming, encoding-aware redaction of secret values.
//
// The redactor sits between the child process's PTY and the response that goes
// back to the agent.  It has to work on a stream (output arrives in arbitrary
// chunks) and it has to catch a value even when the program that printed it
// mangled the bytes on the way out: colour codes spliced into the middle,
// base64 with line wrapping, URL escaping, shell quoting.
//
// Everything index-sensitive works on []rune rather than bytes.  A multi-byte
// character inside a value would otherwise let a byte-offset slice cut a rune
// in half, and the halves would not match anything.
package redact

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// --------------------------------------------------------------------------
// Stage 1: ANSI / control-character stripping
// --------------------------------------------------------------------------

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

// StripANSI removes escape sequences and normalises CRLF.  Not stream-safe on
// its own; see stripANSIStream.
func StripANSI(text string) string {
	return strings.ReplaceAll(ansiRE.ReplaceAllString(text, ""), "\r\n", "\n")
}

// stripANSIStream strips escapes from buf, holding back a possibly-incomplete
// tail.  The returned carry must be prepended to the next chunk because it may
// be the beginning of an escape sequence (or a lone "\r" that could turn out to
// be the first half of a CRLF).
func stripANSIStream(buf []rune) (clean string, carry []rune) {
	carryStart := len(buf)
	esc := -1
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] == '\x1b' {
			esc = i
			break
		}
	}
	if esc != -1 && len(buf)-esc <= maxEscapeLen {
		// Only hold back if the sequence is not obviously already terminated.
		tail := string(buf[esc:])
		if loc := ansiRE.FindStringIndex(tail); loc == nil || loc[0] != 0 {
			carryStart = esc
		}
	}
	if carryStart == len(buf) && len(buf) > 0 && buf[len(buf)-1] == '\r' {
		carryStart = len(buf) - 1
	}
	return StripANSI(string(buf[:carryStart])), buf[carryStart:]
}

// --------------------------------------------------------------------------
// Stage 2: the expanded value set
// --------------------------------------------------------------------------

// Base64Variants returns the base64 encodings of value: standard and URL-safe,
// padded and not.
func Base64Variants(value string) map[string]bool {
	raw := []byte(value)
	out := map[string]bool{}
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
	} {
		out[enc] = true
		out[strings.TrimRight(enc, "=")] = true
	}
	return out
}

// percentEncode mirrors Python's urllib.parse.quote(value, safe="").
// Unreserved characters are the ASCII letters, digits, and "_.-~".
func percentEncode(value string, plus bool) string {
	var b strings.Builder
	for _, c := range []byte(value) {
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == '~':
			b.WriteByte(c)
		case plus && c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// shlexUnsafe matches Python's shlex.quote find set: anything outside
// [\w@%+=:,./-] forces quoting.
var shlexUnsafe = regexp.MustCompile(`[^\w@%+=:,./-]`)

// shlexQuote mirrors Python's shlex.quote.
func shlexQuote(value string) string {
	if value == "" {
		return "''"
	}
	if !shlexUnsafe.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// jsonEscape returns the JSON string encoding of value without the quotes.
func jsonEscape(value string) string {
	// SetEscapeHTML(false) keeps <, > and & literal, matching Python's
	// json.dumps, so the variant we match is the one ordinary tools print.
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return value
	}
	s := strings.TrimRight(b.String(), "\n")
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

// Variants returns every rendering of value the redactor knows how to
// recognise.
//
// Deliberately not exhaustive: an agent that wants to defeat this can (see the
// threat model).  These are the encodings ordinary tools produce by accident:
// JSON output, URLs, "set -x" traces, base64 dumps.
func Variants(value string) map[string]bool {
	out := map[string]bool{value: true}
	for v := range Base64Variants(value) {
		out[v] = true
	}
	out[percentEncode(value, false)] = true
	out[percentEncode(value, true)] = true
	out[jsonEscape(value)] = true
	out[shlexQuote(value)] = true
	// Body of a shell single-quoted string.
	out[strings.ReplaceAll(value, "'", `'\''`)] = true
	// Body of a shell double-quoted string.
	dq := strings.ReplaceAll(value, `\`, `\\`)
	dq = strings.ReplaceAll(dq, `"`, `\"`)
	dq = strings.ReplaceAll(dq, `$`, `\$`)
	dq = strings.ReplaceAll(dq, "`", "\\`")
	out[dq] = true

	delete(out, "")
	return out
}

// --------------------------------------------------------------------------
// Stage 3: eligibility -- refuse to redact values that would eat the output
// --------------------------------------------------------------------------

// ShannonEntropy returns entropy in bits per character.
func ShannonEntropy(value string) float64 {
	runes := []rune(value)
	if len(runes) == 0 {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range runes {
		counts[r]++
	}
	n := float64(len(runes))
	total := 0.0
	for _, c := range counts {
		p := float64(c) / n
		total -= p * math.Log2(p)
	}
	return total
}

type EligibilityPolicy struct {
	MinLength             int
	MinUniqueChars        int
	MinEntropyBitsPerChar float64
}

func DefaultPolicy() EligibilityPolicy {
	return EligibilityPolicy{MinLength: 8, MinUniqueChars: 4, MinEntropyBitsPerChar: 1.5}
}

// Check returns "" if the value may be redacted, else the reason it may not.
func (p EligibilityPolicy) Check(value string) string {
	runes := []rune(value)
	if len(runes) < p.MinLength {
		return fmt.Sprintf("shorter than %d characters", p.MinLength)
	}
	unique := map[rune]bool{}
	for _, r := range runes {
		unique[r] = true
	}
	if len(unique) < p.MinUniqueChars {
		return fmt.Sprintf("fewer than %d distinct characters", p.MinUniqueChars)
	}
	if e := ShannonEntropy(value); e < p.MinEntropyBitsPerChar {
		return fmt.Sprintf("low entropy (%.2f bits/char)", e)
	}
	return ""
}

// TokenFor is the stable placeholder a secret is replaced with.  Stable across
// turns and across processes so the model can reason about "the router
// password" without ever seeing it.
func TokenFor(ref string) string { return "«SECRET:" + ref + "»" }

// --------------------------------------------------------------------------
// Stage 4: the streaming redactor
// --------------------------------------------------------------------------

type entry struct {
	ref     string
	token   string
	pattern *regexp.Regexp
	wrapped *regexp.Regexp
	longest int
}

// Count is one row of the wire response's "redactions" field.
type Count struct {
	Token string `json:"token"`
	Count int    `json:"count"`
}

// Redactor replaces every known secret rendering with a stable token.
//
// Feed withholds a tail of the stream so a value split across two reads is
// still caught; Flush releases it.
type Redactor struct {
	Policy  EligibilityPolicy
	Overlap int

	counts    map[string]int
	entries   []entry
	ansiCarry []rune
	buf       []rune
}

// Secret is one (ref, value) pair fed to the redactor.
type Secret struct {
	Ref   string
	Value string
}

// New builds a redactor over the given secrets.  A value the policy refuses is
// not matched; naming it is the store's job, which is where the operator-facing
// refusal list comes from.
func New(secrets []Secret, policy EligibilityPolicy) *Redactor {
	r := &Redactor{Policy: policy, counts: map[string]int{}}
	seen := map[string]bool{}
	for _, s := range secrets {
		if seen[s.Value] {
			continue
		}
		if policy.Check(s.Value) != "" {
			continue
		}
		seen[s.Value] = true
		r.entries = append(r.entries, compile(s.Ref, s.Value))
	}
	// Longest value first: if one secret is a substring of another, the longer
	// token must win.
	sort.SliceStable(r.entries, func(i, j int) bool {
		return r.entries[i].longest > r.entries[j].longest
	})
	longest := 0
	for _, e := range r.entries {
		if e.longest > longest {
			longest = e.longest
		}
	}
	// x2 covers base64 line wrapping (newlines inserted inside a value), +16
	// covers quoting expansion at a chunk boundary.
	r.Overlap = longest*2 + 16
	return r
}

// alternation builds a pattern matching any of vs, longest first.  Go's
// regexp uses leftmost-first alternation, so ordering by length descending is
// what makes the longest rendering win.
func alternation(vs []string) *regexp.Regexp {
	sort.SliceStable(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	quoted := make([]string, len(vs))
	for i, v := range vs {
		quoted[i] = regexp.QuoteMeta(v)
	}
	return regexp.MustCompile(strings.Join(quoted, "|"))
}

func compile(ref, value string) entry {
	var vs []string
	for v := range Variants(value) {
		vs = append(vs, v)
	}
	sort.Strings(vs) // deterministic before the length sort
	pattern := alternation(vs)

	var b64 []string
	for v := range Base64Variants(value) {
		b64 = append(b64, v)
	}
	sort.Strings(b64)
	var wrapped *regexp.Regexp
	if len(b64) > 0 {
		wrapped = alternation(b64)
	}

	longest := 0
	for _, v := range vs {
		if n := len([]rune(v)); n > longest {
			longest = n
		}
	}
	return entry{ref: ref, token: TokenFor(ref), pattern: pattern, wrapped: wrapped, longest: longest}
}

// Feed absorbs a chunk of raw output and returns the part that is safe to emit.
func (r *Redactor) Feed(text string) string {
	if text == "" {
		return ""
	}
	r.ansiCarry = append(r.ansiCarry, []rune(text)...)
	clean, carry := stripANSIStream(r.ansiCarry)
	r.ansiCarry = carry
	r.buf = []rune(r.redact(string(r.buf) + clean))
	if len(r.buf) > r.Overlap {
		out := string(r.buf[:len(r.buf)-r.Overlap])
		r.buf = r.buf[len(r.buf)-r.Overlap:]
		return out
	}
	return ""
}

// Flush releases everything held back.  Call once, at end of stream.
func (r *Redactor) Flush() string {
	tail := StripANSI(string(r.ansiCarry))
	r.ansiCarry = nil
	out := r.redact(string(r.buf) + tail)
	r.buf = nil
	return out
}

// RedactText is a one-shot convenience for text that is already complete.
func (r *Redactor) RedactText(text string) string { return r.Feed(text) + r.Flush() }

// Summary is the "redactions" field of the wire response: tokens and counts,
// never values.
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

func (r *Redactor) redact(text string) string {
	if text == "" {
		return text
	}
	// Built at most once per distinct text rather than once per secret.  Every
	// entry needs the same newline-free view of the same haystack, and building
	// it is linear in the chunk: doing that per entry made the whole pass
	// quadratic in the size of the store, which is the number that grows without
	// anyone watching it.
	//
	// Invalidated only when an entry actually replaced something, which is why
	// the plain pass below keeps the old string when it matched nothing.  Most
	// secrets appear in no given chunk, so in practice this is built once.
	var view *collapsedView
	for i := range r.entries {
		e := &r.entries[i]
		if e.wrapped != nil {
			if view == nil {
				view = newCollapsedView(text)
			}
			if out, changed := r.subWrapped(view, e); changed {
				text = out
				view = nil
			}
		}
		n := 0
		replaced := e.pattern.ReplaceAllStringFunc(text, func(string) string {
			n++
			return e.token
		})
		// Assigned only on a hit.  ReplaceAllStringFunc allocates a copy even
		// when it matched nothing, and taking that copy would throw the view
		// away on every entry, which is the cost this is avoiding.
		if n > 0 {
			text = replaced
			r.counts[e.token] += n
			view = nil
		}
	}
	return text
}

// collapsedView is one haystack with its line breaks taken out, plus what is
// needed to map a match in it back onto the original.
//
// base64 output is wrapped at 76 columns, so a value that was encoded and
// printed arrives with newlines inside it and matches nothing as written.
// Matching happens against view; the span that gets replaced is in the original,
// so the surrounding output survives.
type collapsedView struct {
	// runes is the original, indexed the way the spans below are.
	runes []rune
	view  string
	// byteStart maps a byte offset in view to the index in runes of the rune
	// that begins there, with one extra entry for the end.  A slice rather than
	// a map keyed on the same thing: it is filled once, read at most twice per
	// match, and a map of one entry per byte was most of what this cost.
	byteStart []int
	// collapsed is false when there were no line breaks to take out, in which
	// case the plain pass already covers everything this would find.
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

// subWrapped replaces every line-wrapped rendering of one secret, and reports
// whether it changed anything.
func (r *Redactor) subWrapped(v *collapsedView, e *entry) (string, bool) {
	if !v.collapsed {
		return "", false
	}
	type span struct{ start, end int }
	var spans []span
	for _, loc := range e.wrapped.FindAllStringIndex(v.view, -1) {
		if loc[1] <= loc[0] {
			continue
		}
		// The first rune of the match, and one past the last: byteStart is
		// indexed by byte, so the end comes from the last byte of the match
		// rather than from the offset after it.
		start, end := v.byteStart[loc[0]], v.byteStart[loc[1]-1]+1
		if strings.ContainsAny(string(v.runes[start:end]), "\n\r") {
			spans = append(spans, span{start, end})
		}
	}
	if len(spans) == 0 {
		return "", false
	}

	var b strings.Builder
	cursor := 0
	for _, s := range spans {
		if s.start < cursor { // overlapping match, already covered
			continue
		}
		b.WriteString(string(v.runes[cursor:s.start]))
		b.WriteString(e.token)
		r.counts[e.token]++
		cursor = s.end
	}
	b.WriteString(string(v.runes[cursor:]))
	return b.String(), true
}
