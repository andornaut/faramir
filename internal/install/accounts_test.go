package install

import (
	"os"
	"path/filepath"
	"testing"
)

// The store group holds nologin service accounts and belongs in the system
// range, below GID_MIN.  Reading the wrong number here either warns about a
// group that is fine or stays quiet about one that will collide with whatever
// the host allocates next.
func TestFirstLoginGID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    int
	}{
		{
			// What Debian and Ubuntu ship: GID_MIN set, the system range
			// commented out, which is why it is GID_MIN that is read.
			name: "shipped",
			content: "UID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n" +
				"GID_MIN\t\t\t 1000\nGID_MAX\t\t\t60000\n" +
				"#SYS_GID_MIN\t\t  100\n#SYS_GID_MAX\t\t  999\n",
			want: 1000,
		},
		{
			name:    "raised",
			content: "GID_MIN 5000\n",
			want:    5000,
		},
		{
			// Prefixed, so the field name does not match and the value it
			// carries is not the one in force.
			name:    "commented out",
			content: "#GID_MIN 5000\n",
			want:    1000,
		},
		{
			name:    "unparseable",
			content: "GID_MIN notanumber\n",
			want:    1000,
		},
		{
			name:    "absent",
			content: "UID_MIN 1000\n",
			want:    1000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "login.defs")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			previous := loginDefs
			t.Cleanup(func() { loginDefs = previous })
			loginDefs = path

			if got := firstLoginGID(); got != tc.want {
				t.Errorf("firstLoginGID() = %d, want %d", got, tc.want)
			}
		})
	}
}

// A host with no login.defs at all still has to answer, because the answer
// decides whether a store group is reported as misallocated.
func TestFirstLoginGIDWithoutLoginDefs(t *testing.T) {
	previous := loginDefs
	t.Cleanup(func() { loginDefs = previous })
	loginDefs = filepath.Join(t.TempDir(), "absent")

	if got := firstLoginGID(); got != 1000 {
		t.Errorf("firstLoginGID() = %d, want 1000", got)
	}
}
