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
	// The strict spelling of the link's kind, the strictness being what the
	// kind carries: a survivor kept as the loose kind would be refused as the
	// loose one whatever its Strict field said.
	if rules[0].Kind != KindLinkedStrict {
		t.Errorf("the surviving rule is %q, want the link written strict", rules[0].Kind)
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

// A kind added to the constants and left out of Kinds() is the one drift the
// single catalogue exists to prevent, and it fails asymmetrically: the broker
// would sort the rule first and enforce it, while the guard rendered nothing for
// it, so the tier an agent meets is the one that failed open. Loud at the point
// it happens rather than silent on a host.
func TestARuleOfAnUnlistedKindIsRefusedRatherThanDropped(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a rule whose kind is not in Kinds() was accepted, so the guard " +
				"renders no rule for it while the broker enforces one")
		}
	}()
	GuardRules([]Rule{{Kind: Kind("nosuchkind"), Patterns: []string{`\bexample\b`}}})
}

// Every kind Kinds() lists survives the same call, so the check above refuses an
// unlisted kind rather than refusing everything.
func TestEveryListedKindIsAccepted(t *testing.T) {
	for _, kind := range Kinds() {
		rules := []Rule{{Kind: kind, Patterns: []string{`\bexample\b`}}}
		if got := GuardRules(rules); len(got) != 1 {
			t.Errorf("kind %q rendered %d rules, want 1", kind, len(got))
		}
	}
}

// An entry's strictness is its kind, both tiers keying off that vocabulary and
// the guard having nothing else to read: a strict entry rendered as the loose
// kind is refused with the message written for the loose one, which offers a
// brokered route the broker will not give it.
func TestAnEntrysStrictnessIsItsKind(t *testing.T) {
	rules := For("", nil, config.SecretConfig{
		Blocked: []config.BlockedPath{
			{Path: "/srv/keys/loose.key"},
			{Path: "/srv/keys/strict.key", Strict: true},
		},
		Links: []config.Link{
			{Ref: "loose", Path: "/srv/links/loose.pem", Type: "raw"},
			{Ref: "strict", Path: "/srv/links/strict.pem", Type: "raw", Strict: true},
		},
	})
	want := map[string]Kind{
		"/srv/keys/loose.key":   KindBlocked,
		"/srv/keys/strict.key":  KindBlockedStrict,
		"/srv/links/loose.pem":  KindLinked,
		"/srv/links/strict.pem": KindLinkedStrict,
	}
	got := map[string]Kind{}
	for _, rule := range rules {
		got[rule.Entry] = rule.Kind
	}
	for entry, kind := range want {
		if got[entry] != kind {
			t.Errorf("%s is kind %q, want %q", entry, got[entry], kind)
		}
	}
}
