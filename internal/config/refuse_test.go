package config

import (
	"strings"
	"testing"
)

func TestRefusedPathsLoad(t *testing.T) {
	cfg, err := load(t, minimal+`
[secret]

[[secret.refuse]]
path = "/etc/luks/volume.key"

[[secret.refuse]]
path = "/home/operator/.ssh"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Refused) != 2 {
		t.Fatalf("refused = %v, want two", cfg.Secret.Refused)
	}
	if cfg.Secret.Refused[0].Path != "/etc/luks/volume.key" {
		t.Errorf("first = %+v", cfg.Secret.Refused[0])
	}
	if cfg.Secret.Refused[1].Path != "/home/operator/.ssh" {
		t.Errorf("second = %+v", cfg.Secret.Refused[1])
	}
}

// A path that is not there loads. These are keys on volumes that are not always
// mounted, and refusing one would refuse the case the entry exists for.
func TestARefusedPathNeedNotExist(t *testing.T) {
	cfg, err := load(t, minimal+`
[[secret.refuse]]
path = "/mnt/nothing-is-mounted-here/luks.key"
`)
	if err != nil {
		t.Fatalf("an absent path was refused at load: %v", err)
	}
	if len(cfg.Secret.Refused) != 1 {
		t.Fatalf("refused = %v, want one", cfg.Secret.Refused)
	}
}

// Every refusal names the entry and says what to write instead, a config being
// something an operator fixes by hand.
func TestRefusedPathValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"no path":      {`[[secret.refuse]]`, "path or name is required"},
		"empty path":   {"[[secret.refuse]]\npath = \"\"", "path or name is required"},
		"relative":     {"[[secret.refuse]]\npath = \"etc/luks.key\"", "is relative"},
		"a home":       {"[[secret.refuse]]\npath = \"~/.ssh/id_ed25519\"", "starts with ~"},
		"not cleaned":  {"[[secret.refuse]]\npath = \"/etc/./luks.key\"", "shortest form"},
		"a trailing /": {"[[secret.refuse]]\npath = \"/home/op/.ssh/\"", "shortest form"},
		"the whole fs": {"[[secret.refuse]]\npath = \"/\"", "every file on the host"},
		"an unknown key": {"[[secret.refuse]]\npath = \"/a/b\"\ntype = \"text\"",
			"type"},
		"two of one path": {"[[secret.refuse]]\npath = \"/a/b\"\n\n[[secret.refuse]]\npath = \"/a/b\"",
			"more than one entry"},
		"not a table": {"[secret]\nrefuse = \"/a/b\"", "expected [[secret.refuse]] tables"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, minimal+"\n"+tc.body+"\n")
			if err == nil {
				t.Fatalf("loaded, want a refusal naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// The suggested spelling has to be one the loader then accepts, or the refusal
// sends the operator round again.
func TestTheCleanedPathARefusalSuggestsIsAccepted(t *testing.T) {
	_, err := load(t, minimal+"\n[[secret.refuse]]\npath = \"/home/op/.ssh/\"\n")
	if err == nil {
		t.Fatal("a trailing slash loaded")
	}
	if !strings.Contains(err.Error(), `"/home/op/.ssh"`) {
		t.Fatalf("the refusal does not name the spelling to use: %v", err)
	}
	if _, err := load(t, minimal+"\n[[secret.refuse]]\npath = \"/home/op/.ssh\"\n"); err != nil {
		t.Errorf("the spelling it suggested is refused too: %v", err)
	}
}

// BaseRefusedPaths is what a command about to rewrite config.toml reads first, so a
// re-run keeps the entries rather than erasing them.
func TestBaseRefusedReadsTheEntriesBack(t *testing.T) {
	path := writeBase(t, minimal+`
[[secret.refuse]]
path = "/etc/luks/volume.key"
`)
	refused, err := BaseRefusedPaths(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) != 1 || refused[0].Path != "/etc/luks/volume.key" {
		t.Fatalf("BaseRefusedPaths = %+v", refused)
	}
}

// A first install has no file, which is not an error: there is nothing to keep.
func TestBaseRefusedOnAFileThatIsNotThere(t *testing.T) {
	refused, err := BaseRefusedPaths(t.TempDir() + "/config.toml")
	if err != nil {
		t.Fatalf("a first install reported an error: %v", err)
	}
	if len(refused) != 0 {
		t.Fatalf("BaseRefusedPaths = %+v, want nothing", refused)
	}
}

// A name entry's own rules. The failure this guards runs the other way from a
// path's: a pattern that matches everything refuses the agent every file it can
// name, which is the answer "/" gets as a path.
func TestRefusedNameValidation(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"both forms":       {"[[secret.refuse]]\npath = \"/etc/k\"\nname = \"k\"", "one or the other"},
		"everything":       {"[[secret.refuse]]\nname = \"*\"", "every file on the host"},
		"every file again": {"[[secret.refuse]]\nname = \"*/*\"", "every file on the host"},
		"an absolute path": {"[[secret.refuse]]\nname = \"/etc/k\"", "absolute path"},
		"a tilde":          {"[[secret.refuse]]\nname = \"~/.ssh/id_rsa\"", "nothing expands"},
		"a globstar":       {"[[secret.refuse]]\nname = \"**/k\"", "already matches in"},
		"a dot segment":    {"[[secret.refuse]]\nname = \"../k\"", ".. segment"},
		"padded":           {"[[secret.refuse]]\nname = \" k \"", "whitespace"},
		"two of one name": {"[[secret.refuse]]\nname = \"k\"\n\n[[secret.refuse]]\nname = \"k\"",
			"more than one entry"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, minimal+"\n"+tc.body+"\n")
			if err == nil {
				t.Fatalf("loaded, want a refusal naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// The shapes that load, and the fact that a name and a path may sit beside each
// other: one entry is one or the other, a config is both.
func TestRefusedNamesLoad(t *testing.T) {
	cfg, err := load(t, minimal+`
[[secret.refuse]]
path = "/etc/luks/volume.key"

[[secret.refuse]]
name = "*.htpasswd"

[[secret.refuse]]
name = ".storage/"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Refused) != 3 {
		t.Fatalf("refused = %v, want three", cfg.Secret.Refused)
	}
	if got := cfg.Secret.Refused[1].Name; got != "*.htpasswd" {
		t.Errorf("second names %q", got)
	}
	if got := cfg.Secret.Refused[1].Refuses(); got != "*.htpasswd" {
		t.Errorf("Refuses() = %q, want the name", got)
	}
	if got := cfg.Secret.Refused[0].Refuses(); got != "/etc/luks/volume.key" {
		t.Errorf("Refuses() = %q, want the path", got)
	}
}
