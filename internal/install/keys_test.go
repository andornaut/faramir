package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An existing .sops.yaml is kept, applying a changed rule meaning every managed
// value is re-encrypted.  Kept and read back, so --age-recipient on an installed
// host does not read as applied when it was not.
func TestKeepSopsConfigReportsWhatTheFileActuallySays(t *testing.T) {
	const (
		keeper = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
		backup = "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg"
	)
	for _, tc := range []struct {
		name string
		// listed is the file on disk; requested is --age-recipient plus the
		// keeper's own.
		listed    []string
		requested []string
		keeper    string
		want      []string
		warns     []string
		noWarn    bool
	}{
		{
			name:   "asking for what is already there",
			listed: []string{keeper, backup}, requested: []string{backup, keeper},
			keeper: keeper, want: []string{keeper, backup}, noWarn: true,
		},
		{
			// Names the key it did not add, the next move being to add it by
			// hand.
			name:   "a recipient asked for and not in the file",
			listed: []string{keeper}, requested: []string{backup, keeper},
			keeper: keeper, want: []string{keeper},
			warns: []string{"--age-recipient", backup, "updatekeys"},
		},
		{
			// What replacing the age key leaves behind: every value from now on
			// is one the keeper cannot read.
			name:   "the file has drifted off the keeper's key",
			listed: []string{backup}, requested: []string{keeper},
			keeper: keeper, want: []string{backup},
			warns: []string{"does not list the keeper", keeper, "redacts nothing"},
		},
		{
			// Nothing read the key, so nothing is claimed about it.  A dry run
			// and a removed key both land here.
			name:   "the keeper's recipient is unknown",
			listed: []string{backup}, requested: nil,
			keeper: "", want: []string{backup}, noWarn: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			run := &runner{
				layout: Layout{ConfigDir: dir, KeeperUser: "faramir-keeper",
					AgeKeyPath: filepath.Join(dir, "age.key")},
				opts:            Options{AgeRecipients: tc.requested},
				keeperRecipient: tc.keeper,
			}
			writeRule(t, run.layout.SopsConfigPath(), tc.listed...)

			run.keepSopsConfig(run.layout.SopsConfigPath())

			if got := strings.Join(run.report.AgeRecipients, " "); got != strings.Join(tc.want, " ") {
				t.Errorf("reported recipients = %q, want %q: the report answers who "+
					"can decrypt, which is what the file lists and not what was asked for",
					run.report.AgeRecipients, tc.want)
			}
			warnings := strings.Join(run.report.Warnings, "\n")
			if tc.noWarn {
				if warnings != "" {
					t.Errorf("warned about a file that says what was asked of it: %s", warnings)
				}
				return
			}
			if warnings == "" {
				t.Fatal("kept the file and said nothing, which is the whole bug")
			}
			for _, want := range tc.warns {
				if !strings.Contains(warnings, want) {
					t.Errorf("warning does not say %q: %s", want, warnings)
				}
			}
		})
	}
}

// A file sops could not parse is reported as a question unasked, an empty
// recipient list reading identically to a rule naming nobody.
func TestKeepSopsConfigDoesNotInventAnAnswerForAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	run := &runner{
		layout:          Layout{ConfigDir: dir, KeeperUser: "faramir-keeper"},
		opts:            Options{AgeRecipients: []string{"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"}},
		keeperRecipient: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
	}
	path := run.layout.SopsConfigPath()
	// An unclosed flow sequence, which is what a hurried hand edit leaves.
	if err := os.WriteFile(path, []byte("creation_rules:\n  - key_groups: [oh dear\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Never fatal: failing here leaves no way to reach the host to fix it.
	run.keepSopsConfig(path)
	if len(run.report.AgeRecipients) != 0 {
		t.Errorf("reported %q from a file it could not read", run.report.AgeRecipients)
	}
	if len(run.report.Warnings) == 0 {
		t.Error("read nothing and said nothing")
	}
}

// [ssh] keys accumulates across config.d, so the list holds paths this install
// did not mint.  Those are checked and refused, never taken over: a drop-in may
// name a key under the operator's own home.
func TestOwnSSHKeyRepairsOnlyWhatItMinted(t *testing.T) {
	newKey := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "id_ed25519")
		for _, half := range []string{path, path + ".pub"} {
			if err := os.WriteFile(half, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	// The broker's uid is this test's own, so the repair needs no root: what
	// separates the two cases is the flag, not the privilege.
	run := &runner{
		brokerUID: os.Getuid(), brokerGID: os.Getgid(),
		layout: Layout{BrokerUser: DefaultBrokerUser},
	}

	t.Run("a key it did not mint is refused", func(t *testing.T) {
		path := newKey(t)

		changed, err := run.ownSSHKey(path, false)

		if err == nil {
			t.Fatal("ownSSHKey() = nil, want a refusal: 0644 is not a key the broker can hold")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("ownSSHKey() = %v, want the path named so it can be fixed", err)
		}
		if changed {
			t.Error("reported a change while refusing to make one")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("mode = %04o, want 0644 left alone", got)
		}
	})

	t.Run("a minted key is repaired, once", func(t *testing.T) {
		path := newKey(t)

		changed, err := run.ownSSHKey(path, true)

		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Error("ownSSHKey() reported no change, want the repair counted")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("mode = %04o, want 0600", got)
		}
		// A second run is a no-op, so an install that changed nothing does not
		// report a restart it does not need.
		if changed, err = run.ownSSHKey(path, true); err != nil || changed {
			t.Errorf("ownSSHKey() = %v, %v, want false, nil on an already-correct key",
				changed, err)
		}
	})

	t.Run("a missing public half names both", func(t *testing.T) {
		path := newKey(t)
		if err := os.Remove(path + ".pub"); err != nil {
			t.Fatal(err)
		}

		_, err := run.ownSSHKey(path, true)

		if err == nil || !strings.Contains(err.Error(), "ssh-keygen -y") {
			t.Errorf("ownSSHKey() = %v, want the command that regenerates the public half", err)
		}
	})
}
