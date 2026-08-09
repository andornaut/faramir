package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An existing .sops.yaml is kept, because applying a changed rule means
// re-encrypting every managed value and an installer doing that would drop a
// reader mid-run.  Keeping it in silence is the part that was wrong: the run
// then reported a set of recipients it had not looked at, so --age-recipient on
// an installed host read as applied for as long as nobody tried the key.
func TestKeepSopsConfigReportsWhatTheFileActuallySays(t *testing.T) {
	const (
		keeper = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
		backup = "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg"
	)
	for _, tc := range []struct {
		name string
		// listed is what the file on disk says; requested is what the run was
		// asked for, as --age-recipient plus the keeper's own.
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
			// The flag that meant nothing.  It has to name the key it did not
			// add, because the operator's next move is to add it by hand.
			name:   "a recipient asked for and not in the file",
			listed: []string{keeper}, requested: []string{backup, keeper},
			keeper: keeper, want: []string{keeper},
			warns: []string{"--age-recipient", backup, "updatekeys"},
		},
		{
			// The severe one: what replacing the age key leaves behind.  Every
			// value encrypted from now on is one the keeper cannot read.
			name:   "the file has drifted off the keeper's key",
			listed: []string{backup}, requested: []string{keeper},
			keeper: keeper, want: []string{backup},
			warns: []string{"does not list the keeper", keeper, "redacts nothing"},
		},
		{
			// Nothing read the key, so nothing is claimed about it.  A dry run
			// and a removed key both land here, and both are reported where they
			// happen rather than guessed at again.
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

// A file sops itself could not parse is one this cannot answer for either, so it
// reports the question as unasked rather than reporting an empty recipient list,
// which reads identically to a rule that names nobody.
func TestKeepSopsConfigDoesNotInventAnAnswerForAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	run := &runner{
		layout:          Layout{ConfigDir: dir, KeeperUser: "faramir-keeper"},
		opts:            Options{AgeRecipients: []string{"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"}},
		keeperRecipient: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
	}
	path := run.layout.SopsConfigPath()
	// Valid YAML for a rule file and not valid as one: an unclosed flow
	// sequence, which is what a hand edit in a hurry leaves behind.
	if err := os.WriteFile(path, []byte("creation_rules:\n  - key_groups: [oh dear\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Never fatal: the file is the operator's to edit, and failing the install
	// over one this cannot parse leaves no way to reach the host that has to be
	// fixed.
	run.keepSopsConfig(path)
	if len(run.report.AgeRecipients) != 0 {
		t.Errorf("reported %q from a file it could not read", run.report.AgeRecipients)
	}
	if len(run.report.Warnings) == 0 {
		t.Error("read nothing and said nothing")
	}
}
