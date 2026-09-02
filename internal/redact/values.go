package redact

// The set of renderings a redactor searches for, built once from the values
// and shared by every redactor over them.

import (
	"sort"
	"strings"
)

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
