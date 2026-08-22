package config

import (
	"strings"
	"testing"
)

func TestBlockedPathsLoad(t *testing.T) {
	cfg, err := load(t, minimal+`
[secret]

[[secret.block]]
path = "/etc/luks/volume.key"

[[secret.block]]
path = "/home/operator/.ssh"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Blocked) != 2 {
		t.Fatalf("refused = %v, want two", cfg.Secret.Blocked)
	}
	if cfg.Secret.Blocked[0].Path != "/etc/luks/volume.key" {
		t.Errorf("first = %+v", cfg.Secret.Blocked[0])
	}
	if cfg.Secret.Blocked[1].Path != "/home/operator/.ssh" {
		t.Errorf("second = %+v", cfg.Secret.Blocked[1])
	}
}

// A path that is not there loads. These are keys on volumes that are not always
// mounted, and refusing one would refuse the case the entry exists for.
func TestABlockedPathNeedNotExist(t *testing.T) {
	cfg, err := load(t, minimal+`
[[secret.block]]
path = "/mnt/nothing-is-mounted-here/luks.key"
`)
	if err != nil {
		t.Fatalf("an absent path was refused at load: %v", err)
	}
	if len(cfg.Secret.Blocked) != 1 {
		t.Fatalf("refused = %v, want one", cfg.Secret.Blocked)
	}
}

// Every refusal names the entry and says what to write instead, a config being
// something an operator fixes by hand.
func TestBlockedPathValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"no path":      {`[[secret.block]]`, "path, name or command is required"},
		"empty path":   {"[[secret.block]]\npath = \"\"", "path, name or command is required"},
		"relative":     {"[[secret.block]]\npath = \"etc/luks.key\"", "is relative"},
		"a home":       {"[[secret.block]]\npath = \"~/.ssh/id_ed25519\"", "starts with ~"},
		"not cleaned":  {"[[secret.block]]\npath = \"/etc/./luks.key\"", "shortest form"},
		"a trailing /": {"[[secret.block]]\npath = \"/home/op/.ssh/\"", "shortest form"},
		"the whole fs": {"[[secret.block]]\npath = \"/\"", "every file on the host"},
		"an unknown key": {"[[secret.block]]\npath = \"/a/b\"\ntype = \"text\"",
			"type"},
		"two of one path": {"[[secret.block]]\npath = \"/a/b\"\n\n[[secret.block]]\npath = \"/a/b\"",
			"more than one entry"},
		"not a table": {"[secret]\nblock = \"/a/b\"", "expected [[secret.block]] tables"},
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
	_, err := load(t, minimal+"\n[[secret.block]]\npath = \"/home/op/.ssh/\"\n")
	if err == nil {
		t.Fatal("a trailing slash loaded")
	}
	if !strings.Contains(err.Error(), `"/home/op/.ssh"`) {
		t.Fatalf("the refusal does not name the spelling to use: %v", err)
	}
	if _, err := load(t, minimal+"\n[[secret.block]]\npath = \"/home/op/.ssh\"\n"); err != nil {
		t.Errorf("the spelling it suggested is refused too: %v", err)
	}
}

// BaseBlocked is what a command about to rewrite config.toml reads first, so a
// re-run keeps the entries rather than erasing them.
func TestBaseRefusedReadsTheEntriesBack(t *testing.T) {
	path := writeBase(t, minimal+`
[[secret.block]]
path = "/etc/luks/volume.key"
`)
	refused, err := BaseBlocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) != 1 || refused[0].Path != "/etc/luks/volume.key" {
		t.Fatalf("BaseBlocked = %+v", refused)
	}
}

// A first install has no file, which is not an error: there is nothing to keep.
func TestBaseRefusedOnAFileThatIsNotThere(t *testing.T) {
	refused, err := BaseBlocked(t.TempDir() + "/config.toml")
	if err != nil {
		t.Fatalf("a first install reported an error: %v", err)
	}
	if len(refused) != 0 {
		t.Fatalf("BaseBlocked = %+v, want nothing", refused)
	}
}

// A name entry's own rules. The failure this guards runs the other way from a
// path's: a pattern that matches everything refuses the agent every file it can
// name, which is the answer "/" gets as a path.
func TestBlockedNameValidation(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"both forms":       {"[[secret.block]]\npath = \"/etc/k\"\nname = \"k\"", "an entry is one of them"},
		"everything":       {"[[secret.block]]\nname = \"*\"", "every file on the host"},
		"every file again": {"[[secret.block]]\nname = \"*/*\"", "every file on the host"},
		"an absolute path": {"[[secret.block]]\nname = \"/etc/k\"", "absolute path"},
		"a tilde":          {"[[secret.block]]\nname = \"~/.ssh/id_rsa\"", "nothing expands"},
		"a globstar":       {"[[secret.block]]\nname = \"**/k\"", "already matches in"},
		"a dot segment":    {"[[secret.block]]\nname = \"../k\"", ".. segment"},
		"padded":           {"[[secret.block]]\nname = \" k \"", "whitespace"},
		"two of one name": {"[[secret.block]]\nname = \"k\"\n\n[[secret.block]]\nname = \"k\"",
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
func TestBlockedNamesLoad(t *testing.T) {
	cfg, err := load(t, minimal+`
[[secret.block]]
path = "/etc/luks/volume.key"

[[secret.block]]
name = "*.htpasswd"

[[secret.block]]
name = ".storage/"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Blocked) != 3 {
		t.Fatalf("refused = %v, want three", cfg.Secret.Blocked)
	}
	if got := cfg.Secret.Blocked[1].Name; got != "*.htpasswd" {
		t.Errorf("second names %q", got)
	}
	if got := cfg.Secret.Blocked[1].Blocks(); got != "*.htpasswd" {
		t.Errorf("Blocks() = %q, want the name", got)
	}
	if got := cfg.Secret.Blocked[0].Blocks(); got != "/etc/luks/volume.key" {
		t.Errorf("Blocks() = %q, want the path", got)
	}
}

// A command entry through the loader, which is the half the struct-level tests
// cannot see: "command" was missing from the accepted keys for as long as the
// form existed, so every one of these was refused at load while the code that
// renders them was covered and green.
func TestABlockedCommandLoads(t *testing.T) {
	cfg, err := load(t, minimal+`
[[secret.block]]
command = "op read"

[[secret.block]]
name = "*.pem"

[[secret.block]]
path = "/etc/luks/volume.key"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Blocked) != 3 {
		t.Fatalf("blocked = %v, want three", cfg.Secret.Blocked)
	}
	if got := cfg.Secret.Blocked[0].Command; got != "op read" {
		t.Errorf("first names command %q", got)
	}
	if got := cfg.Secret.Blocked[0].Blocks(); got != "op read" {
		t.Errorf("Blocks() = %q, want the command", got)
	}
	// And the other two are untouched by the third form existing.
	if cfg.Secret.Blocked[1].Name != "*.pem" || cfg.Secret.Blocked[2].Path != "/etc/luks/volume.key" {
		t.Errorf("the other forms did not load: %+v", cfg.Secret.Blocked)
	}
}
