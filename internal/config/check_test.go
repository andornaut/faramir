package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A wildcard in a link path is refused. The path is opened as written, so
// nothing resolves it, and it renders into the deny rules as a literal, so the
// rule refuses a command typing that pattern and leaves the files it names
// readable. Both failures are silent, and the config is where they are visible.
func TestAWildcardInALinkPathIsRefused(t *testing.T) {
	for _, path := range []string{
		"/home/op/.config/*/token.json",
		"/home/op/tokens/*.json",
		"/home/op/tokens/id_rs?",
		"/home/op/tokens/[a].json",
	} {
		err := ValidateLink(Link{Ref: "a/b", Path: path, Type: "json", Key: "k"})
		if err == nil {
			t.Errorf("%s was accepted, and nothing would resolve it", path)
			continue
		}
		if !strings.Contains(err.Error(), "as written") {
			t.Errorf("%s: the refusal does not say why: %v", path, err)
		}
	}
}

// And an ordinary link path is untouched.
func TestAnOrdinaryLinkPathIsStillAccepted(t *testing.T) {
	for _, path := range []string{
		"/home/op/.npmrc",
		"/home/op/.config/gh/hosts.yml",
		"/srv/tokens-2024/app.json",
	} {
		if err := ValidateLink(Link{Ref: "a/b", Path: path, Type: "json", Key: "k"}); err != nil {
			t.Errorf("%s was refused: %v", path, err)
		}
	}
}

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

// strict is how strictly one entry is matched, so it belongs on the two
// forms that name a file. A command entry is already matched wherever a command
// starts: there is no looser reading of it to tighten, and accepting the key
// while changing nothing would leave an operator sure they had closed
// something.
func TestStrictIsRefusedOnACommandEntry(t *testing.T) {
	body := minimal + "\n[[secret.block]]\ncommand = \"op read\"\nstrict = true\n"
	_, err := load(t, body)
	if err == nil {
		t.Fatal("a command entry carrying strict was accepted")
	}
	for _, want := range []string{"strict", "command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// The two forms that do take it, and the default: absent is the looser reading,
// which is what every entry written before this key existed means.
func TestStrictLoadsOnAPathAndDefaultsOff(t *testing.T) {
	cfg, err := load(t, minimal+"\n[[secret.block]]\npath = \"/home/op/.private\"\n"+
		"strict = true\n\n[[secret.block]]\npath = \"/srv/certs\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Blocked) != 2 {
		t.Fatalf("blocked = %+v, want two entries", cfg.Secret.Blocked)
	}
	if !cfg.Secret.Blocked[0].Strict {
		t.Error("the entry that asked for strict did not get it")
	}
	if cfg.Secret.Blocked[1].Strict {
		t.Error("an entry that did not ask for it got it anyway")
	}
}

// A value of another type is refused rather than read as false: an entry saying
// strict = "yes" means to close something, and taking it as absent leaves
// a host the operator believes is closed and is not.
func TestStrictRefusesAValueThatIsNotABoolean(t *testing.T) {
	_, err := load(t, minimal+"\n[[secret.block]]\npath = \"/home/op/.private\"\n"+
		"strict = \"yes\"\n")
	if err == nil {
		t.Fatal("strict = \"yes\" was accepted")
	}
	if !strings.Contains(err.Error(), "true or false") {
		t.Errorf("the refusal does not say what it wanted: %v", err)
	}
}
