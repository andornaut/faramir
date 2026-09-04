package denyrules

import (
	"strings"
	"testing"
)

// `block ls` prints the description in place of the pattern, so a rule with
// none is a line the listing cannot render. Held here rather than in the
// command: a pattern added to a group without its sentence is a catalogue
// omission, and the catalogue is what says so.
func TestEveryActionPatternSaysWhatItRefuses(t *testing.T) {
	var patterns int
	for _, rule := range ActionRules() {
		for _, pattern := range rule.Patterns {
			patterns++
			what := DescribeAction(pattern)
			if what == "" {
				t.Errorf("the action rule %q says nothing about what it refuses", pattern)
				continue
			}
			// A sentence rather than the rule again. A description holding the
			// pattern is the line the listing exists to replace.
			if strings.Contains(what, `\b`) || strings.Contains(what, `\s`) {
				t.Errorf("the description of %q is a pattern rather than a phrase: %q", pattern, what)
			}
		}
	}
	if patterns == 0 {
		t.Fatal("no action patterns, so this test asserts nothing")
	}
}

// A pattern the catalogue does not carry gets no description, so the listing
// falls back to printing the entry rather than an empty line. Every rule
// generated from the config arrives here.
func TestAPatternTheCatalogueDoesNotCarryIsNotDescribed(t *testing.T) {
	if what := DescribeAction(`\bnot-a-faramir-rule\b`); what != "" {
		t.Errorf("an unknown pattern was described as %q", what)
	}
}
