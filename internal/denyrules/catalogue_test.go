package denyrules

import (
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// A path may carry both entries, and the link is the one that stays. What the
// dropped entry still has to carry is its strictness: the two are two readings
// of one path, the stricter is what the pair asked for, and a merge that keeps
// the looser one takes back a flag the operator set.
func TestTheStricterOfAnOverlappingPairSurvives(t *testing.T) {
	rules := For("", nil, config.SecretConfig{
		Blocked: []config.BlockedPath{{Path: "/srv/keys/luks.key", Strict: true}},
		Links: []config.Link{{
			Ref: "luks", Path: "/srv/keys/luks.key", Type: "raw"}},
	})
	if len(rules) != 1 {
		t.Fatalf("%d rules for one path, want the link alone", len(rules))
	}
	if rules[0].Kind != KindLinked {
		t.Errorf("the surviving rule is %q, want the link", rules[0].Kind)
	}
	if !rules[0].Strict {
		t.Fatal("the block was written strict and the merged rule is not, so a " +
			"brokered `ls` on it is allowed where the entry asked for a refusal")
	}
	// And the shape that follows from it, which is what the flag actually buys.
	re := regexp.MustCompile(rules[0].Broker()[0])
	if !re.MatchString("ls -l /srv/keys/luks.key") {
		t.Error("the merged rule reads as the looser kind on the brokered tier")
	}
}

// A kind that carries subjects has to be rendered, whichever kind it is. One
// collected and never emitted is the failure the single catalogue exists to
// make impossible, and it would be silent.
func TestEveryKindWithSubjectsIsRendered(t *testing.T) {
	for _, kind := range Kinds() {
		rules := []Rule{{Kind: kind, Subjects: []string{Dir("/srv/keys")}}}
		got := GuardRules(rules)
		if len(got) != 1 {
			t.Errorf("kind %q with a subject rendered %d rules, want 1", kind, len(got))
			continue
		}
		if !strings.Contains(got[0], KindMarker(kind)) {
			t.Errorf("the rule for kind %q does not carry its own marker: %s", kind, got[0])
		}
	}
}

// A rule carries subjects or whole patterns, never both and never neither. Both
// tiers branch on which, so a rule holding both silently drops half of itself in
// each of them: half a rule reaching both tiers is the failure the one catalogue
// exists to prevent, and it would be invisible.
func TestARuleCarriesOneShapeOrTheOther(t *testing.T) {
	rules := For("/home/op", []string{"/etc/example"}, config.SecretConfig{
		Blocked: []config.BlockedPath{
			{Path: "/home/op/.private"},
			{Path: "/srv/keys/luks.key", Strict: true},
			{Command: "op read"},
		},
		Links: []config.Link{{Ref: "npm", Path: "/home/op/.npmrc", Type: "ini", Key: "k"}},
	})
	if len(rules) != 5 {
		t.Fatalf("%d rules, want one per entry plus the own directory", len(rules))
	}
	for _, rule := range rules {
		switch {
		case len(rule.Subjects) == 0 && len(rule.Patterns) == 0:
			t.Errorf("the %q rule for %q carries neither subjects nor patterns, so "+
				"it refuses nothing on either tier", rule.Kind, rule.Entry)
		case len(rule.Subjects) > 0 && len(rule.Patterns) > 0:
			t.Errorf("the %q rule for %q carries both, and each tier takes only one "+
				"of them", rule.Kind, rule.Entry)
		}
	}
}
