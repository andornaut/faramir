package guard

import "testing"

func TestGroupedNamesAreSanctionedAsTwoTokens(t *testing.T) {
	for _, cmd := range []string{
		"faramir vault edit /etc/faramir/secrets/a.sops.yml",
		"faramir sops   edit /etc/faramir/secrets/a.sops.yml",
		"faramir link add gh/token /home/o/.config/gh/hosts.yml",
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
	if _, denied := decide("faramir sops cat /etc/faramir/age.key"); !denied {
		t.Error("an unlisted subcommand was sanctioned by its parent")
	}
}
