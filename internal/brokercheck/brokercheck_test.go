package brokercheck

// What the report says.

import (
	"strings"
	"testing"
)

// The refs are named in both messages, so the operator is told which value to
// lengthen rather than that something is wrong.
func TestRefusedRefsNamesEveryRefAndItsReason(t *testing.T) {
	var r CheckReport
	r.Secrets.NotRedactable = map[string]string{
		"short/pin": "shorter than 8 characters",
		"api/kid":   "shorter than 8 characters",
	}
	got := r.RefusedRefs()
	for _, want := range []string{"short/pin", "api/kid", "shorter than 8 characters"} {
		if !strings.Contains(got, want) {
			t.Errorf("RefusedRefs() = %q, missing %q", got, want)
		}
	}
	// Sorted: a map's order would make the message differ between two runs on
	// one unchanged host.
	if !strings.HasPrefix(got, "api/kid") {
		t.Errorf("RefusedRefs() = %q, want the refs in a stable order", got)
	}
}
