package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The keeper execs sops rather than linking it, which is what keeps every cloud
// KMS SDK sops supports out of what we ship. That is a shipping invariant
// rather than a style rule: an import added anywhere this binary reaches pulls
// the whole set in, and nothing else would notice.
func TestTheShippedBinaryDoesNotLinkSops(t *testing.T) {
	for _, dep := range deps(t, ".") {
		if strings.Contains(dep, "getsops") {
			t.Errorf("the command links %s; the keeper is meant to exec sops instead", dep)
		}
	}
}

// The same invariant one level up. The test fixtures run the real sops rather
// than building one out of the libraries, so nothing in the module needs them
// and go.mod names none: a require added here is what would let the check above
// start having something to find, and it would arrive with the AWS, GCP, Azure
// and Vault SDKs behind it.
func TestTheModuleRequiresNoSopsLibrary(t *testing.T) {
	body, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	mod := string(body)
	// The read is held to a module that is required, so a go.mod this stopped
	// being able to parse fails here rather than reporting every absence as a
	// pass.
	if !strings.Contains(mod, "filippo.io/age") {
		t.Fatal("go.mod does not name filippo.io/age, so this is not reading what it thinks it is")
	}
	if strings.Contains(mod, "getsops") {
		t.Error("go.mod requires a getsops module; the fixtures are meant to run the " +
			"sops binary, and linking the libraries puts every cloud KMS SDK back in " +
			"the module")
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
