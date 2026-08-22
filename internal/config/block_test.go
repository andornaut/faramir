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

// Every entry form, written into a config.toml and read back out of it.
//
// The boundary the rest of the suite does not cross. Tests that build a
// BlockedPath in Go exercise everything downstream of the loader and nothing
// in it, so a key missing from blockKeys, a loader that drops a field, or a
// template writing the wrong key name is invisible to all of them. "command"
// was absent from blockKeys for as long as the form existed, and every test
// covering it was green.
func TestEveryBlockedFormRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		form  string
		entry string
		want  BlockedPath
	}{
		{"path", `path = "/etc/luks/volume.key"`, BlockedPath{Path: "/etc/luks/volume.key"}},
		{"name", `name = "*.pem"`, BlockedPath{Name: "*.pem"}},
		{"suffix name", `name = "id_rsa"`, BlockedPath{Name: "id_rsa"}},
		{"directory name", `name = ".storage/"`, BlockedPath{Name: ".storage/"}},
		{"command", `command = "op read"`, BlockedPath{Command: "op read"}},
		{"command with a flag", `command = "sops -d"`, BlockedPath{Command: "sops -d"}},
	} {
		t.Run(tc.form, func(t *testing.T) {
			cfg, err := load(t, minimal+"\n[[secret.block]]\n"+tc.entry+"\n")
			if err != nil {
				t.Fatalf("a %s entry did not load: %v", tc.form, err)
			}
			if len(cfg.Secret.Blocked) != 1 {
				t.Fatalf("loaded %d entries, want one", len(cfg.Secret.Blocked))
			}
			if got := cfg.Secret.Blocked[0]; got != tc.want {
				t.Errorf("loaded %+v, want %+v", got, tc.want)
			}
			// And what a message or a listing shows for it.
			if got := cfg.Secret.Blocked[0].Blocks(); got == "" {
				t.Error("Blocks() is empty, so nothing that names an entry can name this one")
			}
		})
	}
}

// The same for a link, which has four keys and the same exposure.
func TestEveryLinkFieldRoundTrips(t *testing.T) {
	cfg, err := load(t, minimal+`
[[secret.link]]
ref = "gh/token"
path = "/home/op/.config/gh/hosts.yml"
type = "yaml"
key = "github.com/oauth_token"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Links) != 1 {
		t.Fatalf("loaded %d links, want one", len(cfg.Secret.Links))
	}
	want := Link{
		Ref:  "gh/token",
		Path: "/home/op/.config/gh/hosts.yml",
		Type: "yaml",
		Key:  "github.com/oauth_token",
	}
	if got := cfg.Secret.Links[0]; got != want {
		t.Errorf("loaded %+v, want %+v", got, want)
	}
}

// A rendered deny rule is one line of a generated file, and the entry is
// interpolated into it. A newline in an entry ends that line and starts a
// second with the rest, so one rule becomes two fragments, both of them
// unbalanced regular expressions that will not compile. A pattern that does not
// compile is skipped at load, so the entry an operator added to refuse one more
// file silently takes the rules protecting the install with it.
func TestAnEntryCarryingAControlCharacterIsRefused(t *testing.T) {
	for _, blocked := range []BlockedPath{
		{Name: "aaa\nbbb"},
		{Name: "aaa\rbbb"},
		{Name: "aaa\x1bcbbb"},
		{Name: "aaa\x7fbbb"},
		{Path: "/tmp/aaa\nbbb"},
		{Path: "/tmp/aaa\rbbb"},
		{Command: "opread\nsecondline"},
		{Command: "op\x1bcread here"},
	} {
		if err := ValidateBlocked(blocked); err == nil {
			t.Errorf("%+v was accepted, so its rule renders across two lines", blocked)
		}
	}
}

// And an ordinary entry still loads, in every form. The check is about the
// bytes a rule cannot carry, not about narrowing what may be blocked.
func TestAnOrdinaryEntryIsStillAccepted(t *testing.T) {
	for _, blocked := range []BlockedPath{
		{Name: "*.pem"},
		{Name: ".env*"},
		{Name: "secrets*.yml"},
		{Name: ".storage/"},
		{Name: "\u65e5\u672c\u8a9e"},
		{Path: "/etc/luks/volume.key"},
		{Path: "/tmp/a b"},
		{Command: "op read"},
	} {
		if err := ValidateBlocked(blocked); err != nil {
			t.Errorf("%+v was refused: %v", blocked, err)
		}
	}
}

// The refusal has to say which byte and where: an entry pasted from somewhere
// else carries one that prints as nothing, so a message naming only the entry
// reads as a refusal of text that looks fine.
func TestTheControlRefusalNamesTheByte(t *testing.T) {
	err := ValidateBlocked(BlockedPath{Name: "aaa\nbbb"})
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{`\n`, "offset 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %s: %v", want, err)
		}
	}
}
