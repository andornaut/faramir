package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The keeper execs sops rather than linking it, which is what keeps every cloud
// KMS SDK sops supports out of what we ship. That is a shipping invariant
// rather than a style rule: an import added anywhere this binary reaches pulls
// the whole set in, and nothing else would notice.
//
// internal/sopstest links the libraries on purpose, to build a stand-in for the
// suite. This asks what the shipped command reaches, not what the module holds.
func TestTheShippedBinaryDoesNotLinkSops(t *testing.T) {
	for _, dep := range deps(t, ".") {
		if strings.Contains(dep, "getsops") {
			t.Errorf("the command links %s; the keeper is meant to exec sops instead", dep)
		}
	}
}

// The check above passes when nothing matches, which is also what it would do
// if `go list` returned nothing at all. This holds it to a package that does
// link sops, so a matcher that stopped matching fails here rather than passing
// everywhere.
func TestTheSopsCheckMatchesAPackageThatLinksIt(t *testing.T) {
	found := false
	for _, dep := range deps(t, "../../internal/sopstest/sopsenc") {
		if strings.Contains(dep, "getsops") {
			found = true
			break
		}
	}
	if !found {
		t.Error("sopsenc reaches no getsops package, so the check above proves nothing")
	}
}

func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}
