package redact

import (
	"sort"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// matcher finds every rendering of every value in a haystack, in one pass over
// it whatever the size of the set.
//
// An Aho-Corasick automaton rather than a regexp alternation. Every rendering
// is a literal, so no regexp feature is in play, and Go's regexp compiles a
// large literal alternation into a DFA whose cost per byte grows with the
// number of alternatives: 256 KiB of output took 23 ms against one secret and
// 599 ms against 256, where the automaton is flat in the size of the set.
//
// The library returns every match, overlapping ones included. Which of them to
// take is the security-relevant part, so leftmost-longest is decided here in
// code that can be read rather than by a flag: a rendering that contains
// another must win, or the shorter one is replaced and the rest of the longer
// value is left in the output.
type matcher struct {
	trie *ahocorasick.Trie
}

func newMatcher(all []rendering) *matcher {
	patterns := make([]string, 0, len(all))
	for _, r := range all {
		patterns = append(patterns, r.text)
	}
	return &matcher{trie: ahocorasick.NewTrieBuilder().AddStrings(patterns).Build()}
}

// span is one match, as byte offsets into the haystack it was found in.
type span struct{ start, end int }

// find returns the non-overlapping leftmost-longest matches, in the order they
// appear. Nothing is returned for a haystack with no match, which is the
// ordinary case and the one worth not allocating for.
func (m *matcher) find(text string) []span {
	hits := m.trie.MatchString(text)
	if len(hits) == 0 {
		return nil
	}
	all := make([]span, 0, len(hits))
	for _, hit := range hits {
		start := int(hit.Pos())
		end := start + len(hit.Match())
		// A zero-length rendering would match everywhere and consume nothing. The
		// length gate makes one impossible; this is here so that stays true of the
		// sweep below rather than of the caller.
		if end <= start {
			continue
		}
		all = append(all, span{start: start, end: end})
	}
	// Leftmost first, and at one position the longest first. The automaton emits
	// matches as it reaches their ends, so this is what puts them in the order
	// the sweep needs.
	sort.Slice(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return all[i].end > all[j].end
	})
	out := all[:0]
	cursor := 0
	for _, s := range all {
		if s.start < cursor {
			continue
		}
		out = append(out, s)
		cursor = s.end
	}
	return out
}
