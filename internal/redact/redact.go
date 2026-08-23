// Package redact provides streaming, encoding-aware redaction of secret values.
// See docs/redaction.md.
//
// It works on a stream, output arriving in arbitrary chunks, and has to catch a
// value the printing program mangled on the way out: colour codes spliced in,
// base64 line wrapping, URL escaping, shell quoting.
//
// Everything index-sensitive works on []rune, a byte-offset slice being able to
// cut a multi-byte character in half.
package redact

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
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

// stripANSI removes escape sequences and normalises CRLF. Not stream-safe on
// its own; see stripANSIStream.
func stripANSI(text string) string {
	clean, _ := stripANSIView(text)
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

// stripANSIView removes escape sequences and normalises CRLF, and builds the
// view above in the same walk so the two cannot drift.
func stripANSIView(text string) (string, *escapeView) {
	// Nothing to strip and nothing to normalise, which is most output: the walk
	// below would copy every byte twice to say so.
	if !needsStrip(text) {
		return text, nil
	}
	var clean, view strings.Builder
	clean.Grow(len(text))
	view.Grow(len(text))
	index := make([]int, 0, len(text)+1)
	ev := &escapeView{}
	// A CR is held until the next byte says whether it opened a CRLF. Held
	// across a sequence too, the sequence contributing nothing to the stripped
	// text: that is what makes this the same answer as stripping first and
	// normalising after.
	pendingCR := false
	put := func(chunk string) {
		for i := range len(chunk) {
			b := chunk[i]
			if pendingCR {
				pendingCR = false
				if b != '\n' {
					index = append(index, clean.Len())
					clean.WriteByte('\r')
					view.WriteByte('\r')
				}
			}
			if b == '\r' {
				pendingCR = true
				continue
			}
			index = append(index, clean.Len())
			clean.WriteByte(b)
			view.WriteByte(b)
		}
	}
	prev := 0
	for _, loc := range ansiRE.FindAllStringIndex(text, -1) {
		put(text[prev:loc[0]])
		if seq := text[loc[0]:loc[1]]; strings.HasPrefix(seq, "\x1b[") {
			// At the offset the value's surviving bytes start from, so a match
			// covering this byte and the ones after it maps onto them alone.
			index = append(index, clean.Len())
			view.WriteByte(seq[len(seq)-1])
			ev.lenient = true
		}
		prev = loc[1]
	}
	put(text[prev:])
	if pendingCR {
		index = append(index, clean.Len())
		clean.WriteByte('\r')
		view.WriteByte('\r')
	}
	index = append(index, clean.Len())
	ev.view, ev.clean = view.String(), index
	return clean.String(), ev
}

// withPrefix is the view of prefix+text, for a chunk that is redacted with the
// tail of the one before it in front of it. The prefix is output this redactor
// already wrote, so it is its own view.
func (v *escapeView) withPrefix(prefix string) *escapeView {
	if v == nil || !v.lenient {
		return nil
	}
	index := make([]int, 0, len(prefix)+len(v.clean))
	for i := range len(prefix) {
		index = append(index, i)
	}
	for _, at := range v.clean {
		index = append(index, len(prefix)+at)
	}
	return &escapeView{view: prefix + v.view, clean: index, lenient: true}
}

// stripANSIStream strips escapes from buf, holding back a possibly-incomplete
// tail. The carry must be prepended to the next chunk: it may open an escape
// sequence, or be the first half of a CRLF.
func stripANSIStream(buf []rune) (clean string, ev *escapeView, carry []rune) {
	carryStart := len(buf)
	esc := -1
	for i, r := range slices.Backward(buf) {
		if r == '\x1b' {
			esc = i
			break
		}
	}
	if esc != -1 && len(buf)-esc <= maxEscapeLen {
		// Only hold back a sequence that is not obviously terminated.
		tail := string(buf[esc:])
		if loc := ansiRE.FindStringIndex(tail); loc == nil || loc[0] != 0 {
			carryStart = esc
		}
	}
	if carryStart == len(buf) && len(buf) > 0 && buf[len(buf)-1] == '\r' {
		carryStart = len(buf) - 1
	}
	clean, ev = stripANSIView(string(buf[:carryStart]))
	return clean, ev, buf[carryStart:]
}

// --------------------------------------------------------------------------
// Stage 2: the expanded value set
// --------------------------------------------------------------------------

// base64Variants returns the base64 encodings of value: standard and URL-safe,
// padded and not.
func base64Variants(value string) map[string]bool {
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

// base32Variants returns the RFC 4648 base32 encodings of value, padded and
// not. TOTP seeds and some token formats are base32, and the unpadded form is
// what `otpauth://` URIs carry.
func base32Variants(value string) map[string]bool {
	enc := base32.StdEncoding.EncodeToString([]byte(value))
	return map[string]bool{
		enc:                         true,
		strings.TrimRight(enc, "="): true,
	}
}

// There is deliberately no HTML/XML entity variant. Every other encoding here
// has one spelling or a closed set of them, which is what makes enumerating it
// possible; entity escaping has neither, each character having a named, a
// decimal and a hexadecimal form, and "&#112;" for a plain "p" being as valid
// as leaving it alone. A list of renderings would cover whichever producer it
// was written against and read as coverage of the rest.

// The characters a percent-encoder leaves alone, beyond the unreserved set.
// Which one a producer uses is the whole difference between its output and
// another's, so each is named for the function that has it.
const (
	// safeQuote is Python's urllib.parse.quote(value, safe=""): nothing beyond
	// the unreserved set.
	safeQuote = ""
	// safeComponent is JavaScript's encodeURIComponent.
	safeComponent = "!*'()"
	// safeURI is JavaScript's encodeURI, which is meant to leave a whole URL
	// usable and so keeps the reserved delimiters too.
	safeURI = "!*'();,/?:@&=+$#"
)

// percentEncode renders value the way a percent-encoder would, with safe naming
// the characters left alone beyond the unreserved ASCII letters, digits and
// "_.-~". plus writes a space as "+", which HTML form encoding does. lower emits
// the hex digits in lower case: the RFC prefers upper and most encoders write
// it, but enough write "%3c" that both spellings are worth carrying.
func percentEncode(value, safe string, plus, lower bool) string {
	format := "%%%02X"
	if lower {
		format = "%%%02x"
	}
	var b strings.Builder
	for _, c := range []byte(value) {
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == '~',
			strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		case plus && c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, format, c)
		}
	}
	return b.String()
}

// percentVariants returns every percent-encoded rendering of value: each safe
// set in both hex cases, and the form encoding that writes a space as "+".
// A value holding none of the characters the sets differ over collapses to one
// string, so this costs nothing on the ordinary case.
func percentVariants(value string) map[string]bool {
	out := map[string]bool{}
	for _, safe := range []string{safeQuote, safeComponent, safeURI} {
		for _, lower := range []bool{false, true} {
			out[percentEncode(value, safe, false, lower)] = true
			out[percentEncode(value, safe, true, lower)] = true
		}
	}
	return out
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
	// SetEscapeHTML(false) keeps <, > and & literal, which is what ordinary tools
	// print.
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

// variants returns every rendering of value the redactor recognises. Not
// exhaustive by design (see docs/redaction.md), but the encodings ordinary
// tools produce by accident.
func variants(value string) map[string]bool {
	out := map[string]bool{value: true}
	for v := range base64Variants(value) {
		out[v] = true
	}
	for v := range base32Variants(value) {
		out[v] = true
	}
	// Hex, both cases, contiguous: xxd -p, bytes.hex(), DB BLOB dumps. A
	// dump that separates the bytes is a different string and is not this: see
	// docs/redaction.md.
	h := hex.EncodeToString([]byte(value))
	out[h] = true
	out[strings.ToUpper(h)] = true
	for v := range percentVariants(value) {
		out[v] = true
	}
	js := jsonEscape(value)
	out[js] = true
	// PHP's json_encode and many JSON serializers escape "/" as "\/" by default.
	out[strings.ReplaceAll(js, "/", `\/`)] = true
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
// Stage 3: eligibility. Refuse to redact values that would eat the output
// --------------------------------------------------------------------------

// EligibilityPolicy is the one property of a value this decides: whether it is
// long enough to search output for.
//
// Length only: no distinct-character count and no entropy floor, neither being
// the strength check it reads as ("password" clears both). A short value
// matches inside ordinary words, so redacting it blanks unrelated output; a
// long low-entropy value such as "aaaaaaaa" mangles the operator's output
// rather than letting a value escape.
type EligibilityPolicy struct {
	MinLength int
}

func DefaultPolicy() EligibilityPolicy {
	return EligibilityPolicy{MinLength: 8}
}

// Check returns "" if the value may be redacted, else the reason it may not.
func (p EligibilityPolicy) Check(value string) string {
	if len([]rune(value)) < p.MinLength {
		return fmt.Sprintf("shorter than %d characters", p.MinLength)
	}
	// A value that is faramir's own token, guillemets and all. The redactor
	// emits that shape for another ref, and the streaming buffer redacts the
	// tail it already redacted, so a stored token would be matched there and
	// re-wrapped: a real value's output would carry this ref's token instead of
	// its own. Refused the way a short value is, being a value the redactor
	// cannot represent rather than one it will not hold. No real credential is
	// this shape; it is faramir's reserved output format.
	if strings.HasPrefix(value, tokenOpen) && strings.HasSuffix(value, tokenClose) {
		return "is shaped like faramir's own " + tokenOpen + "…" + tokenClose +
			" token, which the redactor emits and would re-wrap"
	}
	return ""
}

// The delimiters of the token a secret is replaced with. Named so Check refuses
// exactly the shape TokenFor produces.
const (
	tokenOpen  = "«SECRET:"
	tokenClose = "»"
)

// TokenFor is the placeholder a secret is replaced with, stable across turns
// and processes so the model can reason about a value without seeing it.
func TokenFor(ref string) string { return tokenOpen + ref + tokenClose }

// --------------------------------------------------------------------------
// Stage 4: the streaming redactor
// --------------------------------------------------------------------------

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
	// Overlap is the tail a stream holds back, which is a property of the longest
	// rendering rather than of one request.
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

	counts    map[string]int
	ansiCarry []rune
	buf       []rune
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
	// x2 for base64 line wrapping, +16 for quoting expansion at a boundary.
	r.Overlap = longest*2 + 16
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
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Feed absorbs a chunk of raw output and returns the part that is safe to emit.
func (r *Redactor) Feed(text string) string {
	if text == "" {
		return ""
	}
	// Counted before the conversion below, which replaces an invalid byte and so
	// is the last moment one can be told from a U+FFFD the command wrote.
	// Callers report the count rather than act on it.
	r.invalidBytes += invalidUTF8Bytes(text)
	r.ansiCarry = append(r.ansiCarry, []rune(text)...)
	clean, ev, carry := stripANSIStream(r.ansiCarry)
	r.ansiCarry = carry
	held := string(r.buf)
	r.buf = []rune(r.redact(held+clean, ev.withPrefix(held)))
	if len(r.buf) > r.Overlap {
		out := string(r.buf[:len(r.buf)-r.Overlap])
		r.buf = r.buf[len(r.buf)-r.Overlap:]
		return out
	}
	return ""
}

// Flush releases everything held back. Call once, at end of stream.
func (r *Redactor) Flush() string {
	tail, ev := stripANSIView(string(r.ansiCarry))
	r.ansiCarry = nil
	held := string(r.buf)
	out := r.redact(held+tail, ev.withPrefix(held))
	r.buf = nil
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
	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, s := range spans {
		token, ok := r.tokenOf[text[s.start:s.end]]
		if !ok {
			continue // unreachable: the automaton is built from these keys
		}
		b.WriteString(text[cursor:s.start])
		b.WriteString(token)
		r.counts[token]++
		cursor = s.end
	}
	b.WriteString(text[cursor:])
	return b.String()
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
	type span struct {
		start, end int
		token      string
	}
	var spans []span
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
		spans = append(spans, span{start: start, end: end, token: token})
	}
	if len(spans) == 0 {
		return "", false
	}

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, s := range spans {
		if s.start < cursor { // overlapping match, already covered
			continue
		}
		b.WriteString(text[cursor:s.start])
		b.WriteString(s.token)
		r.counts[s.token]++
		cursor = s.end
	}
	b.WriteString(text[cursor:])
	return b.String(), true
}

// subWrapped replaces every line-wrapped rendering, and reports whether it
// changed anything.
// wrappedSpan is one line-spanning match, as offsets into the original runes plus
// the token it stands for. Separate from matcher's span, which is byte offsets
// into the collapsed view.
type wrappedSpan struct {
	start, end int
	token      string
}

func (r *Redactor) subWrapped(v *collapsedView) (string, bool) {
	if !v.collapsed {
		return "", false
	}
	var spans []wrappedSpan
	for _, loc := range r.matcher.find(v.view) {
		token, ok := r.tokenOf[v.view[loc.start:loc.end]]
		if !ok {
			continue // unreachable: the automaton is built from these keys
		}
		// byteStart is indexed by byte, so the end comes from the match's last byte
		// rather than the offset after it.
		start, end := v.byteStart[loc.start], v.byteStart[loc.end-1]+1
		if strings.ContainsAny(string(v.runes[start:end]), "\n\r") {
			spans = append(spans, wrappedSpan{start: start, end: end, token: token})
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
		b.WriteString(s.token)
		r.counts[s.token]++
		cursor = s.end
	}
	b.WriteString(string(v.runes[cursor:]))
	return b.String(), true
}
