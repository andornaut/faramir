package audit

import (
	"os"
	"testing"
)

// Every test in this package runs with the last resort fatal. Reaching it is a
// defect in this repository rather than a condition to survive, so a change that
// puts a record beyond the cap stops here instead of being read about later.
//
// The two tests that reach it on purpose, the ones asserting it still writes a
// record, turn this off around themselves with unstrict().
func TestMain(m *testing.M) {
	strict = true
	os.Exit(m.Run())
}

// unstrict restores the shipped behaviour for one test.
func unstrict() func() {
	strict = false
	return func() { strict = true }
}
