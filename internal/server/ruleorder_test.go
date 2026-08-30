package server

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/guard"
)

// The two tiers answer in the same order. The rendered file puts the action
// rules ahead of the path rules on purpose: a command that is both an operator
// command and a named path is told it is an operator command, that being the
// more useful of the two answers. First match wins on either side, so a broker
// that appended them last explained the same command differently, which is what
// one catalogue exists to stop.
func TestTheOperatorAnswerComesFirst(t *testing.T) {
	const own = "/opt/ownexample"
	check := newDeclaredCheck(append(guard.ActionRules(),
		denyrules.For("", []string{own}, config.SecretConfig{})...))

	rule, refused := check.refuses(
		[]string{"sudo", "faramir", "doctor", "--config", own + "/config.toml"}, "/tmp")
	if !refused {
		t.Fatal("a faramir subcommand under sudo was allowed")
	}
	if rule.Kind != denyrules.KindOperator {
		t.Errorf("it is answered as %q, where the guard answers the same command "+
			"as an operator command", rule.Kind)
	}
}
