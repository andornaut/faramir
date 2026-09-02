// Package hostsudotest pins which sudo a test sees. Imported only from _test.go
// files.
//
// One helper rather than a copy per package that decides by sudo flavour: both
// arrangements have to be exercised on whichever sudo this machine has.
package hostsudotest

import (
	"testing"

	"github.com/andornaut/faramir/internal/hostsudo"
)

// PinSudo answers the sudo-flavour probe for the duration of one test: rs is
// sudo-rs, otherwise stock sudo.
func PinSudo(t *testing.T, rs bool) {
	t.Helper()
	original := hostsudo.RsProbe
	hostsudo.RsProbe = func() bool { return rs }
	t.Cleanup(func() { hostsudo.RsProbe = original })
}
