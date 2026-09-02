package doctor

import (
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/layouttest"
)

// pinSudo answers the sudo-flavour probe for the duration of one test, so both
// arrangements are diagnosed on whichever sudo this machine happens to have.
func pinSudo(t *testing.T, rs bool) {
	t.Helper()
	original := hostsudo.RsProbe
	hostsudo.RsProbe = func() bool { return rs }
	t.Cleanup(func() { hostsudo.RsProbe = original })
}

// testLayout is the install a diagnosis re-renders against. The shared fixture
// rather than one built through Options: what these tests compare is a render
// against a file, and going through the installer to get a layout would put its
// defaults into the comparison.
func testLayout() hostlayout.Layout { return layouttest.Layout() }
