package install

import (
	"os"
	"path/filepath"
	"testing"
)

// The pure parts of the diagnosis. Reaching permissiveAuth through a doctor run
// needs a host whose PAM stack has been made a free pass; the rule it applies is
// a property of the text, so it is checked here as text.

// A fallback stack that authenticates without asking would turn removing
// faramir's service into an open escalation rather than a closed one, so what
// counts as permissive has to be exact.
func TestPermissiveAuthWantsAPermitNothingCanRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a bare permit", "auth required pam_permit.so\n", true},
		{"a permit reached first", "auth sufficient pam_permit.so\nauth required pam_deny.so\n", true},
		{"a permit behind a check that can refuse", "auth required pam_unix.so\nauth required pam_permit.so\n", false},
		{"a deny", "auth required pam_deny.so\n", false},
		{"an include", "auth include common-auth\n", false},
		{"an empty stack", "", false},
		{"only comments", "# nothing here\n# nor here\n", false},
		{"a commented-out permit", "#auth required pam_permit.so\n", false},
		{"a permit in another stack is not an auth line", "account required pam_permit.so\n", false},
		{"a session permit is not an auth line", "session required pam_permit.so\n", false},
		{"leading whitespace is still an auth line", "   auth required pam_permit.so\n", true},
		{"an account line before the auth permit", "account required pam_unix.so\nauth required pam_permit.so\n", true},
		{"no trailing newline", "auth required pam_permit.so", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := permissiveAuth(tc.body); got != tc.want {
				t.Errorf("permissiveAuth(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestDetailWithCountNamesTheCountOnlyWhenSomethingChanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		changed int
		want    string
	}{
		{"nothing changed", "/srv/tree", 0, "/srv/tree"},
		{"one path", "/srv/tree", 1, "/srv/tree (1 path(s) regrouped or rechmodded)"},
		{"many paths", "/srv/tree", 4096, "/srv/tree (4096 path(s) regrouped or rechmodded)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := detailWithCount(tc.path, tc.changed); got != tc.want {
				t.Errorf("detailWithCount(%q, %d) = %q, want %q", tc.path, tc.changed, got, tc.want)
			}
		})
	}
}

// Both ecryptfs layouts, because writing into a home before it is unlocked lands
// in the backing directory and is shadowed the moment the home mounts.
func TestLooksEncryptedRecognisesBothEcryptfsLayouts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, home string)
		want  bool
	}{
		{"a plain home", func(*testing.T, string) {}, false},
		{"a home holding .ecryptfs", func(t *testing.T, home string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(home, ".ecryptfs"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"an .ecryptfs file rather than a directory", func(t *testing.T, home string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(home, ".ecryptfs"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.setup(t, home)
			if got := looksEncrypted(home); got != tc.want {
				t.Errorf("looksEncrypted(%q) = %v, want %v", home, got, tc.want)
			}
		})
	}
}

// A home and its parent on one filesystem is the unmounted case; a mount is what
// puts them on different devices.
func TestHomeIsMountedComparesTheDeviceWithTheParent(t *testing.T) {
	home := t.TempDir()
	if homeIsMounted(home) {
		t.Errorf("%q and its parent are one filesystem, but it read as mounted", home)
	}
	if homeIsMounted(filepath.Join(home, "absent")) {
		t.Error("a home that is not there read as mounted")
	}
}
