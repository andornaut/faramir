package server

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/guard"
)

// The commands that act on the install are the operator's by either route. They
// were the guard's alone, so the shell spelling was refused and the brokered one
// ran: the account on the far side is not the operator either, and a rule the
// two tiers do not share is a rule one of them has never heard of.
func TestABrokeredOperatorCommandIsRefused(t *testing.T) {
	check := newDeclaredCheck(guard.ActionRules())

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

// Every kind gets a message written for it. A kind added to the catalogue and
// not answered here falls to the path branch, which is how a blocked command
// came to be told what a reader may still do to a file.
func TestEveryKindHasARefusalOfItsOwn(t *testing.T) {
	for _, kind := range denyrules.Kinds() {
		entry := denyrules.Rule{Kind: kind, Entry: "/srv/keys/luks.key", Remedy: blockRemoval}
		rule := declaredRule{Rule: entry}
		said := declaredRefusal(rule)
		if said == "" {
			t.Errorf("kind %q has no refusal", kind)
			continue
		}
		// "declared" names no command its reader could run, and does not say
		// which of the two removals applies.
		if strings.Contains(said, "declare") {
			t.Errorf("the refusal for kind %q says something is declared:\n%s", kind, said)
		}
		if list := kind.List(); list != "" && !strings.Contains(said, list) {
			t.Errorf("the refusal for kind %q does not name %q:\n%s", kind, list, said)
		}
	}
}
