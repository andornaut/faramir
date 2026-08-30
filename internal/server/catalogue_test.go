package server

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/denyrules"
)

// The commands that act on the install are the operator's by either route. They
// were the guard's alone, so the shell spelling was refused and the brokered one
// ran: the account on the far side is not the operator either, and a rule the
// two tiers do not share is a rule one of them has never heard of.
func TestABrokeredOperatorCommandIsRefused(t *testing.T) {
	check := newDeclaredCheck(denyrules.ActionRules())

	for _, cmd := range [][]string{
		{"faramir", "vault", "ls"},
		{"sh", "-c", "faramir block add --path /srv/keys"},
		{"sudo", "faramir", "reload"},
		{"sudo", "-u", "faramir-keeper", "cat", "/tmp/x"},
		{"systemctl", "stop", "faramir-broker"},
		{"rm", "/usr/local/bin/faramir"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed through the broker", cmd)
		}
	}

	// Ordinary work that merely names the install is not this. A converge
	// installs faramir without acting on it as a subcommand.
	for _, cmd := range [][]string{
		{"ansible-playbook", "site.yml"},
		{"systemctl", "restart", "faramir-broker"},
		{"ls", "/home/op/src/faramir"},
	} {
		if rule, refused := check.refuses(cmd, "/tmp"); refused {
			t.Errorf("%v was refused as %q", cmd, rule.Kind)
		}
	}
}

// blockRemoval is the removal a block entry carries, spelled apart from the
// literal so this file does not read as an invocation of it: the guard matches
// the text of a command, and a heredoc body is one.
var blockRemoval = "`" + "faramir block" + " rm`"

// Every kind gets a message of its own, in the parts every message has. Asked
// of the parts rather than of the finished string: a message that lost its
// remedy still reads as a sentence, so prose assertions pass on it and only the
// phrases somebody thought to list would catch it.
//
// The tail is what makes a message about a file, so a kind that is not a path
// carrying one is a kind that fell through to the path branch. That is how a
// blocked command came to be told what a reader may still do to a file.
func TestEveryKindHasARefusalOfItsOwn(t *testing.T) {
	for _, kind := range denyrules.Kinds() {
		entry := denyrules.Rule{Kind: kind, Entry: "/srv/keys/luks.key", Remedy: blockRemoval}
		got := refusalFor(declaredRule{Rule: entry})

		if got.body == "" {
			t.Errorf("kind %q says nothing about what it refused", kind)
		}
		// A refusal with nothing to offer sends its reader looking for a way
		// round it, so every kind has one whether or not an entry stands behind
		// the rule.
		if got.remedy == "" {
			t.Errorf("kind %q offers no remedy:\n%s", kind, got.text())
		}
		isPath := kind.DeclaredPath()
		if (got.tail != "") != isPath {
			if isPath {
				t.Errorf("kind %q does not say what its entry leaves alone", kind)
			} else {
				t.Errorf("kind %q falls through to the message written for a path:\n%s",
					kind, got.text())
			}
		}
		// "declared" names no command its reader could run, and does not say
		// which of the two removals applies.
		if said := got.text(); strings.Contains(said, "declare") {
			t.Errorf("the refusal for kind %q says something is declared:\n%s", kind, said)
		}
		// Where an entry stands behind the rule, the refusal names both the
		// listing it is in and the command that takes it back out.
		if list := kind.List(); list != "" {
			if !strings.Contains(got.body, list) {
				t.Errorf("the refusal for kind %q does not name %q:\n%s", kind, list, got.body)
			}
			if !strings.Contains(got.remedy, entry.Remedy) {
				t.Errorf("the refusal for kind %q does not name its removal:\n%s",
					kind, got.remedy)
			}
		}
	}
}
