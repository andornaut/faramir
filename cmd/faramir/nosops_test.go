package main

import (
	"os"
	"strings"
	"testing"
)

// The keeper execs sops rather than linking it, which is what keeps every cloud
// KMS SDK sops supports out of what we ship. That is a shipping invariant
// rather than a style rule: an import added anywhere this binary reaches pulls
// the whole set in, and nothing else would notice. Held at go.mod rather than at
// the binary's dependency list: a package cannot be linked without its module
// being required, so a require is caught before anything imports it, and the
// test fixtures run the real sops so nothing in the module needs one.
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
