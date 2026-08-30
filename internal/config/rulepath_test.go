package config

import "testing"

// A blocked path and a linked path render into the same deny rules, so a
// spelling one refuses the other must refuse too. They did not: a link accepted
// a path in non-shortest form, which the broker opens happily while the rule
// rendered from it matches nothing a command would type, and accepted "/",
// which renders a rule refusing every path on the host.
//
// Asserted as a pair rather than twice over, so a check added to one and not the
// other fails here.
func TestABlockedPathAndALinkedPathAreHeldToTheSameSpelling(t *testing.T) {
	link := func(path string) error {
		return ValidateLink(Link{Ref: "a/b", Path: path, Type: "json", Key: "k"})
	}
	block := func(path string) error {
		return ValidateBlocked(BlockedPath{Path: path})
	}
	for _, tc := range []struct {
		path    string
		refused bool
		why     string
	}{
		{"/srv/keys/k", false, "an ordinary absolute path"},
		{"/srv/./keys/k", true, "a rule matches the path as written, so this one matches nothing"},
		{"/srv/keys/../keys/k", true, "and so does this"},
		{"/", true, "this would refuse every path on the host"},
		{"relative/k", true, "a rule is matched against a path named in full"},
		{"~/k", true, "nothing expands a tilde here"},
		{"/srv/keys/*.k", true, "a pattern is matched as written rather than expanded"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			b, l := block(tc.path) != nil, link(tc.path) != nil
			if b != l {
				t.Errorf("block refused = %v, link refused = %v: the two render the "+
					"same rule and must agree", b, l)
			}
			if b != tc.refused {
				t.Errorf("refused = %v, want %v: %s", b, tc.refused, tc.why)
			}
		})
	}
}
