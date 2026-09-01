package broker

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
)

// The daemon holds the catalogue's action rules, ahead of the ones it builds
// from the config.
//
// Through New rather than through newDeclaredCheck with a list assembled here:
// a test that hands a check its own rules and then asserts them is asserting
// what it configured, and a daemon holding none of them passed every such
// test.
//
// Actions first is the order the guard's rendered file puts them in and is for
// the same reason: a command that is both an operator command and a named path
// is told it is an operator command, that being the more useful of the two
// answers. First match wins on either side, so the order is part of what the
// two tiers share.
func TestTheDaemonHoldsTheActionRulesFirst(t *testing.T) {
	const own = "/opt/ownexample"
	s := New([]string{own}, &config.Config{
		Server:  config.ServerConfig{AgentUser: ""},
		Command: config.CommandConfig{Concurrency: 1},
	})

	rule, refused := s.declared.refuses(
		[]string{"sudo", "faramir", "doctor", "--config", own + "/config.toml"}, "/tmp")
	if !refused {
		t.Fatal("the daemon allowed a faramir subcommand under sudo, so it is " +
			"holding none of the rules about faramir's own commands")
	}
	if rule.Kind != denyrules.KindOperator {
		t.Errorf("the daemon answers it as %q, where the guard answers the same "+
			"command as an operator command", rule.Kind)
	}

	// And the rules New builds for itself are still there, or the assertion
	// above would hold on a daemon that had lost them.
	if _, refused := s.declared.refuses([]string{"cat", own + "/age.key"}, "/tmp"); !refused {
		t.Error("the daemon allowed a command naming one of its own directories")
	}
}
