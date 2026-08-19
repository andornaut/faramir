package sopsrule

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	first  = "age1zvkyg2lc7fyx45ycem9wp2qzcvhhrn6pnhwzcpr0v0y5ea6lyzhs7wcxzn"
	second = "age1dn0q2089z2hrlvlmh7pu8ujn478lehkvw7esqysag0zwea7ffflsd9thv2"
)

func load(t *testing.T, body string) []Rule {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".sops.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rules
}

// sops reads the `age` shorthand only where a rule has no key groups, so a rule
// carrying both seals to its groups and to nobody else. Reading both names a
// reader the rule does not grant: it would re-encrypt a store to a key never
// listed, and would report a keeper still covered by a rule whose groups leave
// it out.
func TestKeyGroupsWinOverTheShorthand(t *testing.T) {
	rules := load(t, "creation_rules:\n  - path_regex: .*\n"+
		"    age: "+first+"\n"+
		"    key_groups:\n      - age:\n          - "+second+"\n")
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if !slices.Equal(rules[0].Recipients, []string{second}) {
		t.Errorf("recipients = %v, want just %s", rules[0].Recipients, second)
	}
}

// However the shorthand is written. A hand-edited file carries whichever of
// these somebody typed, and a reader that takes only one of them reports a
// present key as absent, or refuses a file sops reads.
func TestTheShorthandIsReadInEveryShape(t *testing.T) {
	for _, tc := range []struct{ name, rule string }{
		{"one", "    age: " + first + "\n"},
		{"two, commas", "    age: " + first + ", " + second + "\n"},
		{"a list", "    age:\n      - " + first + "\n      - " + second + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := load(t, "creation_rules:\n  - path_regex: .*\n"+tc.rule)
			if len(rules) != 1 {
				t.Fatalf("rules = %d, want 1", len(rules))
			}
			got := rules[0].Recipients
			if got[0] != first {
				t.Fatalf("recipients = %v, want them to start with %s", got, first)
			}
			if tc.name != "one" && !slices.Equal(got, []string{first, second}) {
				t.Errorf("recipients = %v, want both", got)
			}
		})
	}
}

// Counted however the rules are written: a rule is a list entry whose keys are
// in whatever order somebody typed them, so a reader anchored on path_regex
// reads most of these as one rule. What a caller does with the count is its
// own, but it has to be the real one.
func TestEveryRuleIsCounted(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"path_regex first", "creation_rules:\n" +
			"  - path_regex: prod/.*\n    age: " + first + "\n" +
			"  - path_regex: .*\n    age: " + second + "\n"},
		{"age first", "creation_rules:\n" +
			"  - age: " + first + "\n    path_regex: prod/.*\n" +
			"  - age: " + second + "\n    path_regex: .*\n"},
		{"key_groups first", "creation_rules:\n" +
			"  - key_groups:\n      - age:\n          - " + first + "\n    path_regex: prod/.*\n" +
			"  - key_groups:\n      - age:\n          - " + second + "\n    path_regex: .*\n"},
		{"flow style", `creation_rules: [{path_regex: "prod/.*", age: "` + first +
			`"}, {path_regex: ".*", age: "` + second + `"}]` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rules := load(t, tc.body); len(rules) != 2 {
				t.Errorf("rules = %d, want 2: %+v", len(rules), rules)
			}
		})
	}
}

// Carried rather than acted on here: a caller that would flatten the groups into
// one recipient list has to be able to refuse instead, that turning "N of these
// groups together" into "any one of these keys".
func TestAShamirThresholdIsCarried(t *testing.T) {
	rules := load(t, "creation_rules:\n  - path_regex: .*\n"+
		"    shamir_threshold: 2\n"+
		"    key_groups:\n      - age:\n          - "+first+
		"\n      - age:\n          - "+second+"\n")
	if len(rules) != 1 || rules[0].ShamirThreshold != 2 {
		t.Fatalf("rules = %+v, want one with a threshold of 2", rules)
	}
}

// Across every rule and without repeats, for the caller whose question is only
// whether a key is named in the file at all.
func TestRecipientsAcrossEveryRule(t *testing.T) {
	rules := load(t, "creation_rules:\n"+
		"  - path_regex: prod/.*\n    age: "+first+"\n"+
		"  - path_regex: .*\n    age: "+first+", "+second+"\n")
	if got := Recipients(rules); !slices.Equal(got, []string{first, second}) {
		t.Errorf("Recipients = %v, want %v", got, []string{first, second})
	}
}

// A key group may pull in others through `merge:`, and the keys they name seal
// the file exactly like the ones written inline. Stopping at the top level
// reports a rule as sealing to fewer recipients than it does, and a caller
// re-encrypting from that answer drops every reader named only under a merge:
// silently, and not undone by running it again.
func TestMergedKeyGroupsAreRecipientsToo(t *testing.T) {
	rules := load(t, "creation_rules:\n  - path_regex: .*\n"+
		"    key_groups:\n"+
		"      - age:\n          - "+first+"\n"+
		"        merge:\n          - age:\n              - "+second+"\n")
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if !slices.Equal(rules[0].Recipients, []string{first, second}) {
		t.Errorf("recipients = %v, want both: sops seals with the merged group too",
			rules[0].Recipients)
	}
}

// sops takes a comma-separated string only in a rule's own `age`; a key group's
// is a list. Reading commas there would report recipients from a file sops
// refuses to load, which is this package claiming to know better than the thing
// it exists to agree with.
func TestAKeyGroupTakesNoCommaSeparatedString(t *testing.T) {
	rules := load(t, "creation_rules:\n  - path_regex: .*\n"+
		"    key_groups:\n      - age:\n          - "+first+","+second+"\n")
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if got := rules[0].Recipients; len(got) != 1 || got[0] != first+","+second {
		t.Errorf("recipients = %v, want the entry left as sops reads it", got)
	}
}

// The name decides the store sops parses the probe with, and --filename-override
// is what supplies it, so a YAML body under a .json or .env name is rejected
// before sops has said anything about creation rules.
func TestTheProbeBodyMatchesTheTargetsStore(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"store.sops.yml", "faramir_rule_check: probe"},
		{"store.sops.yaml", "faramir_rule_check: probe"},
		{"store.sops.json", `{"faramir_rule_check": "probe"}`},
		{"store.env", "faramir_rule_check=probe"},
		{"store.ini", "[faramir]"},
	} {
		if got := string(probeBody(tc.target)); !strings.Contains(got, tc.want) {
			t.Errorf("probeBody(%q) = %q, want it to carry %q", tc.target, got, tc.want)
		}
	}
}
