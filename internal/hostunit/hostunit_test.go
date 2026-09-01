package hostunit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
)

// unitDirWith points systemUnitDir at a fixture and writes the files given,
// each name relative to it, so a drop-in is named "faramir-exec.service.d/10.conf".
func unitDirWith(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	original := SystemUnitDir
	SystemUnitDir = dir
	t.Cleanup(func() { SystemUnitDir = original })
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Which account a unit runs as, when a drop-in has something to say about it.
// systemd applies drop-ins after the unit and takes the last assignment, and a
// caller that refuses service accounts as operators has to agree with systemd
// about which account that is: reading the unit alone reported the name the
// template shipped while the executor ran as another.
func TestUnitUserResolvesTheWaySystemdDoes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
		why   string
	}{
		{name: "the unit alone",
			files: map[string]string{"svc.service": "[Service]\nUser=plain\n"},
			want:  "plain", why: "no drop-in to consider"},
		{name: "a drop-in renaming the account",
			files: map[string]string{
				"svc.service":                  "[Service]\nUser=shipped\n",
				"svc.service.d/10-rename.conf": "[Service]\nUser=renamed\n",
			},
			want: "renamed", why: "systemd applies the drop-in after the unit"},
		{name: "the last drop-in wins",
			files: map[string]string{
				"svc.service":             "[Service]\nUser=shipped\n",
				"svc.service.d/10-a.conf": "[Service]\nUser=first\n",
				"svc.service.d/20-b.conf": "[Service]\nUser=second\n",
			},
			want: "second", why: "the drop-ins are read in sorted order"},
		{name: "the last assignment in one file wins",
			files: map[string]string{"svc.service": "[Service]\nUser=early\nUser=late\n"},
			want:  "late", why: "systemd takes the last of two assignments"},
		{name: "a drop-in that says nothing about the account",
			files: map[string]string{
				"svc.service":               "[Service]\nUser=shipped\n",
				"svc.service.d/10-mem.conf": "[Service]\nMemoryMax=1G\n",
			},
			want: "shipped", why: "only User= decides this"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unitDirWith(t, tc.files)
			got, err := User("svc.service")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("unitUser = %q, want %q: %s", got, tc.want, tc.why)
			}
		})
	}
}

// An empty assignment is how systemd unsets one, so it clears what the unit said
// rather than being passed over as a line naming nothing.
func TestAnEmptyUserAssignmentClearsTheAccount(t *testing.T) {
	unitDirWith(t, map[string]string{
		"svc.service":               "[Service]\nUser=shipped\n",
		"svc.service.d/10-off.conf": "[Service]\nUser=\n",
	})
	if account, err := User("svc.service"); err == nil {
		t.Errorf("unitUser = %q, want an error: the drop-in unset the account", account)
	}
}

// A unit that is not installed is an install that is not there, and the error
// names that file rather than a drop-in directory that is also absent.
func TestAnAbsentUnitIsReportedAsTheUnit(t *testing.T) {
	unitDirWith(t, nil)
	if _, err := User("svc.service"); err == nil {
		t.Fatal("an absent unit was read as one naming an account")
	}
}

// What InstalledAccounts is for: the names this host uses, drop-ins included.
// The refusal set in cmd/faramir is built from this, so an account it misses is
// one that can be recorded as the operator.
func TestInstalledAccountsFollowsADropIn(t *testing.T) {
	unitDirWith(t, map[string]string{
		"faramir-broker.service":             "[Service]\nUser=faramir-broker\n",
		"faramir-keeper.service":             "[Service]\nUser=faramir-keeper\n",
		"faramir-exec.service":               "[Service]\nUser=faramir-exec\n",
		"faramir-exec.service.d/10-run.conf": "[Service]\nUser=faramir-runner\n",
	})
	accounts := InstalledAccounts()
	if got := accounts[2]; got != "faramir-runner" {
		t.Errorf("the executor's account is %q, want the drop-in's %q", got, "faramir-runner")
	}
	// And a role whose unit is absent falls back to the standard name, which is
	// what an install that named nothing uses.
	unitDirWith(t, nil)
	for i, want := range []string{hostlayout.DefaultBrokerUser, hostlayout.DefaultKeeperUser, hostlayout.DefaultExecUser} {
		if got := InstalledAccounts()[i]; got != want {
			t.Errorf("with no units, account %d is %q, want the default %q", i, got, want)
		}
	}
}
