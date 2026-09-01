package install

import (
	"testing"

	"github.com/andornaut/faramir/internal/hostsudo"
)

// pinSudo answers the sudo-flavour probe for the duration of one test, so both
// arrangements are exercised on whichever sudo this machine happens to have.
func pinSudo(t *testing.T, rs bool) {
	t.Helper()
	original := hostsudo.RsProbe
	hostsudo.RsProbe = func() bool { return rs }
	t.Cleanup(func() { hostsudo.RsProbe = original })
}
