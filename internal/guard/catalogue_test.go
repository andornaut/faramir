package guard

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/denyrules"
)

// Every kind gets an explanation written for it. A kind added to the catalogue
// and not answered here falls through to the unclassified default, which tells
// an agent to run a removal command for an entry that may not exist.
func TestEveryKindHasAdvice(t *testing.T) {
	for _, kind := range denyrules.Kinds() {
		said, ok := byKind[kind]
		if !ok || said == "" {
			t.Errorf("kind %q has no advice", kind)
			continue
		}
		if !strings.HasPrefix(said, "Blocked: ") {
			t.Errorf("the advice for kind %q does not open like a refusal:\n%s", kind, said)
		}
		// "declared" names no command its reader could run.
		if strings.Contains(said, "declare") {
			t.Errorf("the advice for kind %q says something is declared:\n%s", kind, said)
		}
	}
}

// Each action rule reaches the advice its kind names, in the spelling a refusal
// meets: the rendered line, which is where the kind marker is written. A line
// that carried none fell to the unclassified default, which talks about a
// declared path and offers a removal for an entry that does not exist.
//
// Through adviceFor rather than against the table directly, so this asks the
// question a refusal asks.
func TestEveryActionRuleIsAnsweredByItsKind(t *testing.T) {
	for _, rule := range denyrules.ActionRules() {
		for _, line := range denyrules.GuardRules([]denyrules.Rule{rule}) {
			if got := adviceFor(line); got != byKind[rule.Kind] {
				t.Errorf("the action rule %q is answered as something other than %q",
					shortPattern(line), rule.Kind)
			}
		}
	}
}
