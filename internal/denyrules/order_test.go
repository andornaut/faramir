package denyrules

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The catalogue is in Kinds() order, which is where the order lives. Both tiers
// take it from here, so a command matching two rules is answered the same way on
// each: what acts on the install first, then the install's own directories, then
// the entries.
//
// The fixture paths are named for nothing this host declares. A tail is matched
// wherever it appears, so a fixture borrowing a real entry's name would be
// refused to the tools that edit this file.
func TestTheCatalogueIsInKindsOrder(t *testing.T) {
	rank := make(map[Kind]int, len(Kinds()))
	for i, kind := range Kinds() {
		rank[kind] = i
	}

	rules := Catalogue("/home/op", []string{"/etc/exampleown"}, "", config.SecretConfig{
		Blocked: []config.BlockedPath{
			{Path: "/home/op/.examplestore"},
			{Command: "op read"},
		},
		Links: []config.Link{{
			Ref: "example", Path: "/home/op/.examplerc", Type: "ini", Key: "k"}},
	})

	seen := make([]Kind, 0, len(rules))
	for i, rule := range rules {
		if i > 0 && rank[rule.Kind] < rank[rules[i-1].Kind] {
			t.Fatalf("kind %q comes after %q, which is not the order Kinds() states: %v",
				rule.Kind, rules[i-1].Kind, seen)
		}
		seen = append(seen, rule.Kind)
	}
	if len(seen) == 0 {
		t.Fatal("the catalogue is empty")
	}
	// The action kinds are in it at all, or the assertion above holds on a
	// catalogue that is only the config's half.
	if rank[seen[0]] > rank[KindOperator] {
		t.Errorf("the catalogue opens on %q, so it is holding none of the rules "+
			"about faramir's own commands", seen[0])
	}
}
