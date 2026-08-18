package guard

import "testing"

func TestGroupedNamesAreSanctionedAsTwoTokens(t *testing.T) {
	for _, cmd := range []string{
		"faramir vault refs",
		"faramir vault   refs",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}
	// The parent alone is not a sanctioned call: a subcommand nobody listed has
	// its arguments scanned, which is the point of naming both tokens.
	if _, denied := decide("cat /etc/faramir/secrets/a.sops.yml"); !denied {
		t.Error("a plain read of the store was not denied, so this test proves nothing")
	}
	if _, denied := decide("faramir vault cat /etc/faramir/age.key"); !denied {
		t.Error("an unlisted subcommand was sanctioned by its parent")
	}
	// And a listed sibling does not carry the rest of the group: `vault refs` is
	// the agent's, `vault edit` is the operator's, and they differ by one token.
	if _, denied := decide("faramir vault edit app"); !denied {
		t.Error("an operator subcommand was sanctioned by its agent-facing sibling")
	}
}
