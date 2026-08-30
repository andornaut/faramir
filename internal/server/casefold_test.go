package server

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
)

// Both tiers read the catalogue the same way, case included. The guard compiles
// every pattern case-insensitively; a broker that did not made one inventory
// into two again, and a spelling refused to the shell ran here.
func TestTheBrokerReadsTheCatalogueTheGuardsWay(t *testing.T) {
	check := newDeclaredCheck(append(denyrules.ActionRules(),
		denyrules.For("", nil, config.SecretConfig{
			Blocked: []config.BlockedPath{{Path: "/srv/keys/luks.key"}},
		})...))

	for _, cmd := range [][]string{
		{"SUDO", "faramir", "vault", "edit"},
		{"cat", "/SRV/Keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed, and the guard refuses the same spelling", cmd)
		}
	}

	// The command words are not part of that. denyrules spells them `(?-i:...)`
	// deliberately: a program called CAT is a different program, and matching it
	// would refuse a command this host never had.
	if _, refused := check.refuses([]string{"CAT", "/srv/keys/luks.key"}, "/tmp"); refused {
		t.Error("a reader spelled in capitals was refused, so the vocabulary " +
			"stopped being case-sensitive")
	}
}
