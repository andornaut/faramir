package version

import (
	"os"
	"strings"
	"testing"
)

// The stamp is the only thing that puts a release number on a binary, and a -X
// naming a symbol that is not there does nothing and exits 0: the release would
// publish a binary reporting the "dev" below, and nothing would say so until
// someone ran it. This holds the release config to the symbol this package
// declares, reading the module path rather than spelling it twice.
func TestTheReleaseConfigStampsThisSymbol(t *testing.T) {
	want := "-X " + modulePath(t) + "/internal/version.Version={{.Version}}"
	config, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading the release config: %v", err)
	}
	if !strings.Contains(string(config), want) {
		t.Errorf("the release config does not stamp this package.\nwant ldflags containing: %s", want)
	}
}

// A build made outside a release must not claim to be one. The hazard is a
// hand-edited number left behind after a release, which reports the previous
// version from every working tree until someone edits it again.
func TestTheUnstampedDefaultIsDev(t *testing.T) {
	if Version != "dev" {
		t.Errorf("the unstamped default is %q, want %q", Version, "dev")
	}
}

// releaseVersion is what decides whether an unstamped binary may claim a
// version, and what it claims. It has to reject everything the module system
// records that is not a release, and to spell a release the way the stamp does:
// the two halves reporting one release differently would make the version
// depend on how the binary was installed.
func TestReleaseVersionAcceptsOnlyAReleaseAndDropsThePrefix(t *testing.T) {
	for _, tc := range []struct {
		recorded string
		want     string
	}{
		{"v1.3.4", "1.3.4"},
		{"v0.0.0", "0.0.0"},
		{"v10.20.30", "10.20.30"},
		// A pseudo-version: `go install <module>@main` records one of these.
		{"v1.3.5-0.20260819015529-2246f658d5ff", ""},
		// A build off a modified tree.
		{"v1.3.4+dirty", ""},
		// Built outside the module system.
		{"(devel)", ""},
		{"", ""},
		{"dev", ""},
		{"1.3.4", ""},
		{"v1.3", ""},
		{"v1.3.4.5", ""},
		{"v1.3.x", ""},
		{"v1..4", ""},
		{"v2.0.0+incompatible", ""},
	} {
		if got := releaseVersion(tc.recorded); got != tc.want {
			t.Errorf("releaseVersion(%q) = %q, want %q", tc.recorded, got, tc.want)
		}
	}
}

func modulePath(t *testing.T) string {
	t.Helper()
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for line := range strings.SplitSeq(string(mod), "\n") {
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("go.mod names no module")
	return ""
}

// Mismatch is what every socket says about a caller of another release, so it
// has to name both versions and what to do: a message that says only "refused"
// leaves an operator reading the code to find out why.
func TestMismatchNamesBothVersionsAndTheRemedy(t *testing.T) {
	if why := Mismatch(Version); why != "" {
		t.Errorf("this binary's own version was refused: %s", why)
	}
	for _, tc := range []struct{ name, caller, wants string }{
		{"an older release", "0.1.4", "faramir 0.1.4"},
		{"a newer one", "9.9.9", "faramir 9.9.9"},
		// What a client built before the field sends, which is the case the field
		// exists for.
		{"none at all", "", "no version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			why := Mismatch(tc.caller)
			for _, want := range []string{tc.wants, Version, "restart it"} {
				if !strings.Contains(why, want) {
					t.Errorf("the message does not name %q: %s", want, why)
				}
			}
		})
	}
}
