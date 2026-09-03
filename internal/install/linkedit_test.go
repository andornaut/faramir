package install

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
	"github.com/andornaut/faramir/internal/secretlink"
)

// writeLinkConfig is an install whose config declares the entries given.
func writeLinkConfig(t *testing.T, entries string) string {
	t.Helper()
	return layouttest.ConfigDir(t, "[command]\ntimeout_sec = 600\n"+entries)
}

// Every refusal `link add` can make before it has touched anything: the entry
// is held to what the loader would accept, the ref has to be free, and the file
// has to be there.
//
// Asked in this order and before the grant, which is the point. Each of these
// found afterwards is a file already regrouped for an entry that was never
// written, or a broker refusing every command because one link names nothing.
func TestAddLinkRefusesBeforeItChangesAnything(t *testing.T) {
	present := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(present, []byte("token: a-long-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	taken := "[[secret.link]]\nref = \"gh/token\"\npath = \"" + present + "\"\n" +
		"type = \"yaml\"\nkey = \"token\"\n"

	for _, tc := range []struct {
		name    string
		entries string
		link    config.Link
		wantErr string
	}{
		{
			name:    "a relative path",
			link:    config.Link{Ref: "a/ref", Path: "relative/hosts.yml", Type: secretlink.KindText},
			wantErr: "is relative",
		},
		{
			name:    "a type that selects, with nothing to select",
			link:    config.Link{Ref: "a/ref", Path: present, Type: secretlink.KindYAML},
			wantErr: "key is required",
		},
		{
			// A ref has one definition: two entries claiming one would leave which
			// file a caller reaches decided by the order of the file. The same ref
			// against the same file, type and key is not this, and is re-applied.
			name:    "a ref another entry defines differently",
			entries: taken,
			link:    config.Link{Ref: "gh/token", Path: present, Type: secretlink.KindText},
			wantErr: "already defines gh/token",
		},
		{
			// The file itself answers this one, and it is asked as root, before the
			// grant: a --key naming nothing is a link that was never going to work,
			// and finding it out afterwards leaves a credential file regrouped and
			// the directories above it opened up for an entry never written.
			name:    "a key naming nothing in the file",
			link:    config.Link{Ref: "a/ref", Path: present, Type: secretlink.KindYAML, Key: "oauth_token"},
			wantErr: "this file offers: token",
		},
		{
			// Blocked rather than recorded: a link nothing could verify may refuse
			// every brokered command later, at a moment nobody chose.
			name:    "a file that is not there",
			link:    config.Link{Ref: "a/ref", Path: filepath.Join(t.TempDir(), "gone"), Type: secretlink.KindText},
			wantErr: "mount the home first",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeLinkConfig(t, tc.entries)
			before := readConfigFile(t, dir)

			_, _, err := AddLink(Options{ConfigDir: dir}, tc.link)

			if err == nil {
				t.Fatalf("AddLink accepted %+v", tc.link)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErr)
			}
			if after := readConfigFile(t, dir); after != before {
				t.Errorf("the config was rewritten:\n%s", after)
			}
			// The grant is a mode and a group on the file, and this whole table is
			// the refusals that come before it. A file left regrouped for an entry
			// that was never written is access nothing declares and nothing removes.
			info, statErr := os.Stat(tc.link.Path)
			if statErr != nil {
				return // the cases whose file is not there, or whose path is relative
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("the file's mode became %o, want 600, untouched", got)
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Gid) != os.Getgid() {
				t.Errorf("the file was regrouped to gid %d, want %d, untouched",
					stat.Gid, os.Getgid())
			}
		})
	}
}

// The entry an add finds under the ref it was given, which decides between the
// three answers: write it, re-apply it, or refuse a second definition.
func TestTheEntryAnAddFindsUnderItsRef(t *testing.T) {
	gh := config.Link{Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml",
		Type: secretlink.KindYAML, Key: "token"}

	if _, claimed := linkNamed([]config.Link{gh}, "npm/token"); claimed {
		t.Error("a ref no entry names was reported as claimed")
	}
	other, claimed := linkNamed([]config.Link{gh}, "gh/token")
	if !claimed || other != gh {
		t.Errorf("linkNamed = %+v, %v, want the entry that claims it", other, claimed)
	}

	// Both sides in the message: which credential a caller of that name receives
	// is the whole of what differs, and the ref shows neither.
	err := redefinedRef("/root/.config/faramir/config.toml", gh,
		config.Link{Ref: "gh/token", Path: "/home/op/.netrc", Type: secretlink.KindText})
	for _, want := range []string{"gh/token", "hosts.yml", ".netrc", "yaml token", "text"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
}

// Adding the entry the install already carries is a re-application, not a
// second definition: a configuration manager runs the command on every
// converge. What it re-applies is the grant and the rules, which is why it is
// not answered by doing nothing at all.
func TestAddLinkTakesTheSameEntryTwice(t *testing.T) {
	present := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(present, []byte("token: a-long-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := writeLinkConfig(t, "[[secret.link]]\nref = \"gh/token\"\npath = \""+present+"\"\n"+
		"type = \"yaml\"\nkey = \"token\"\n")

	_, added, err := AddLink(Options{ConfigDir: dir}, config.Link{
		Ref: "gh/token", Path: present, Type: secretlink.KindYAML, Key: "token"})

	if added {
		t.Error("added = true, want the entry recognised as one this install carries")
	}
	// What follows needs the service accounts, so an unprivileged run stops
	// somewhere in the steps. What it must not do is refuse the entry as a
	// redefinition of itself.
	if err != nil && strings.Contains(err.Error(), "already defines") {
		t.Errorf("the same entry twice was refused as a redefinition: %v", err)
	}
}

// Removing a ref the install does not carry writes nothing and reports no
// entry, the caller telling the two apart by that. It is not an error: what was
// asked for is the state the host is in.
func TestRemoveLinkOnARefTheInstallDoesNotCarry(t *testing.T) {
	dir := writeLinkConfig(t, "[[secret.link]]\nref = \"gh/token\"\n"+
		"path = \"/home/operator/.config/gh/hosts.yml\"\ntype = \"yaml\"\nkey = \"token\"\n")
	before := readConfigFile(t, dir)

	_, removed, err := RemoveLink(Options{ConfigDir: dir}, "no/such-ref")

	if err != nil && strings.Contains(err.Error(), "names no link") {
		t.Fatalf("removing a ref the config does not name was an error: %v", err)
	}
	if removed.Ref != "" {
		t.Errorf("removed = %+v, want nothing", removed)
	}
	if after := readConfigFile(t, dir); after != before {
		t.Errorf("the config was rewritten:\n%s", after)
	}
}

// What `link ls` prints is what the config declares, read through the same
// loader the daemons use: a hand-edited entry the daemons would refuse is an
// error here rather than a row in a table.
func TestLinksAreWhatTheConfigDeclares(t *testing.T) {
	dir := writeLinkConfig(t, "[[secret.link]]\nref = \"gh/token\"\n"+
		"path = \"/home/operator/.config/gh/hosts.yml\"\ntype = \"yaml\"\nkey = \"token\"\n")

	links, err := Links(dir)

	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Ref != "gh/token" || links[0].Key != "token" {
		t.Fatalf("links = %+v", links)
	}

	// A first install: the file is not there and that is not an error, an
	// install with no links reading the same as one not made yet.
	links, err = Links(t.TempDir())
	if err != nil {
		t.Fatalf("an install with no config was an error: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("links = %+v, want none", links)
	}

	dir = writeLinkConfig(t, "[[secret.link]]\nref = \"gh/token\"\n"+
		"path = \"relative/hosts.yml\"\ntype = \"text\"\n")
	if _, err := Links(dir); err == nil {
		t.Error("an entry the daemons would refuse was listed as if it worked")
	}
}

// The commands take a directory and join config.toml onto it, and no flag is
// the installed one: a default of "" would join onto nothing and read the
// working directory instead.
func TestTheInstalledConfigDirectoryIsTheDefault(t *testing.T) {
	if got := configDirOr(""); got != hostlayout.DefaultConfigDir {
		t.Errorf("configDirOr(\"\") = %q, want %q", got, hostlayout.DefaultConfigDir)
	}
	if got := configDirOr("/somewhere/else"); got != "/somewhere/else" {
		t.Errorf("configDirOr = %q, want the directory it was given", got)
	}
}

func readConfigFile(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
