package hostlayout

import (
	"os"
	"path/filepath"
	"testing"
)

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
			if got := LooksEncrypted(home); got != tc.want {
				t.Errorf("looksEncrypted(%q) = %v, want %v", home, got, tc.want)
			}
		})
	}
}

// A home and its parent on one filesystem is the unmounted case; a mount is what
// puts them on different devices.
func TestHomeIsMountedComparesTheDeviceWithTheParent(t *testing.T) {
	home := t.TempDir()
	if HomeIsMounted(home) {
		t.Errorf("%q and its parent are one filesystem, but it read as mounted", home)
	}
	if HomeIsMounted(filepath.Join(home, "absent")) {
		t.Error("a home that is not there read as mounted")
	}
}
