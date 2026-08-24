package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Check and Load answer the same question about the same bytes. The installer
// renders config.toml and then replaces the one the daemons read, so a value
// they would refuse has to be caught before the write: afterwards the broker
// cannot start, and `faramir init` refuses to run against a config it cannot
// parse, which leaves an operator with no command that repairs it.
//
// Asserted as one property over both, rather than a list of what Check rejects:
// a rule added to the loader is covered here without anybody remembering this.
func TestCheckRefusesWhatLoadRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"the minimal config", minimal},
		{"a config carrying a link", minimal + oneLink},
		{"a section that is not a section", "[nosuchsection]\nkey = 1\n"},
		{"a key nothing reads", minimal + "\n[server]\nallowed_grp = \"dev\"\n"},
		{"a timeout out of range", "[command]\ntimeout_sec = 0\n"},
		{"a link with a relative path", minimal + "\n[[secret.link]]\nref = \"a/ref\"\n" +
			"path = \"relative\"\ntype = \"text\"\n"},
		{"a notifier that says nothing", minimal + "\n[sudo]\n" +
			"notify_command = [\"/usr/bin/notify-send\", \"faramir\"]\n"},
		{"not TOML at all", "this is not a config\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			_, loadErr := Load(path)
			checkErr := Check([]byte(tc.body), path)

			if (loadErr == nil) != (checkErr == nil) {
				t.Fatalf("Load = %v but Check = %v: the file the installer writes is "+
					"held to different rules than the one the daemons read", loadErr, checkErr)
			}
			if checkErr != nil && !strings.Contains(checkErr.Error(), path) {
				t.Errorf("Check = %v, want it to name the file it is about", checkErr)
			}
		})
	}
}

// Check reads the bytes it is handed and nothing else: it is asked about a
// rendering that has not been written yet, so a file at the path it names need
// not be there at all.
func TestCheckTouchesNoFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-written-yet", "config.toml")

	if err := Check([]byte(minimal), path); err != nil {
		t.Errorf("Check = %v, want the bytes accepted on their own", err)
	}
}
