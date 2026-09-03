package config

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/secretlink"
)

func TestALinkIsLoadedFromTheConfig(t *testing.T) {
	cfg, err := load(t, minimal+`
[secret]

[[secret.link]]
ref = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key = "github.com/oauth_token"

[[secret.link]]
ref = "host/luks"
path = "/home/operator/.private/keyfile"
type = "base64"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secret.Links) != 2 {
		t.Fatalf("links = %v, want two", cfg.Secret.Links)
	}
	first := cfg.Secret.Links[0]
	if first.Ref != "gh/token" || first.Type != "yaml" || first.Key != "github.com/oauth_token" {
		t.Errorf("first link = %+v", first)
	}
	if cfg.Secret.Links[1].Key != "" {
		t.Errorf("a whole-file link carried a key: %+v", cfg.Secret.Links[1])
	}
}

func TestAnInvalidLinkIsRefusedWithAReason(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"no ref": {`
path = "/x"
type = "text"`, "ref is required"},
		"unspellable ref": {`
ref = "/leading-slash"
path = "/x"
type = "text"`, "not valid in a faramir:// reference"},
		"no path": {`
ref = "a/b"
type = "text"`, "path is required"},
		"a home": {`
ref = "a/b"
path = "~/.npmrc"
type = "ini"
key = "k"`, "nothing expands here"},
		"relative path": {`
ref = "a/b"
path = ".npmrc"
type = "ini"
key = "k"`, "is relative"},
		"no type": {`
ref = "a/b"
path = "/x"`, "type is required"},
		"unknown type": {`
ref = "a/b"
path = "/x"
type = "xml"`, `unknown type "xml"`},
		"key required": {`
ref = "a/b"
path = "/x"
type = "json"`, "key is required"},
		"key refused": {`
ref = "a/b"
path = "/x"
type = "text"
key = "k"`, "selects nothing"},
		"unknown key": {`
ref = "a/b"
path = "/x"
type = "text"
selector = "k"`, "unknown key(s): selector"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, minimal+"\n[[secret.link]]"+tc.body+"\n")
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// A ref is the name a caller asks by, so two entries claiming one is refused
// rather than resolved: which won would be an implementation detail of the
// loop that read them.
func TestOneRefClaimedTwiceIsRefused(t *testing.T) {
	_, err := load(t, minimal+`
[[secret.link]]
ref = "gh/token"
path = "/x"
type = "text"

[[secret.link]]
ref = "gh/token"
path = "/y"
type = "text"
`)
	if err == nil {
		t.Fatal("one ref defined twice was accepted")
	}
	if !strings.Contains(err.Error(), "gh/token") {
		t.Errorf("error %q does not name the ref", err)
	}
}

// A scalar where the array of tables goes. Named rather than ignored: the
// entries would be silently absent.
func TestALinkThatIsNotATableIsRefused(t *testing.T) {
	_, err := load(t, minimal+`
[secret]
link = "gh/token"
`)
	if err == nil {
		t.Fatal("a scalar link was accepted")
	}
	if !strings.Contains(err.Error(), "[[secret.link]]") {
		t.Errorf("error %q does not name the shape wanted", err)
	}
}

// Every selecting kind has to survive the loader, not only the reader: a type
// secretlink can extract and the config refuses is one no operator can declare.
func TestEverySelectingKindLoads(t *testing.T) {
	if len(secretlink.Kinds()) == 0 {
		t.Fatal("secretlink extracts no kind, so this asserts nothing")
	}
	for _, kind := range secretlink.Kinds() {
		body := "\nref = \"a/b\"\npath = \"/x\"\ntype = \"" + kind + "\"\n"
		if secretlink.NeedsKey(kind) {
			body += "key = \"k\"\n"
		}
		cfg, err := load(t, minimal+"\n[[secret.link]]"+body)
		if err != nil {
			t.Errorf("type %q is extractable and will not load: %v", kind, err)
			continue
		}
		if len(cfg.Secret.Links) != 1 || cfg.Secret.Links[0].Type != kind {
			t.Errorf("type %q did not round trip: %+v", kind, cfg.Secret.Links)
		}
	}
}

// A link's path is rendered into the agents' deny rules and into the guard's,
// so it carries the hazard a blocked entry does: one rule per line, and a
// newline in the subject splits the rule into fragments that will not compile
// and are skipped, taking the rules that protect the install with them. The key
// never reaches a rule and is held to the same bytes because `faramir link ls`
// prints it back to a terminal.
func TestALinkCarryingAControlCharacterIsRefused(t *testing.T) {
	for _, link := range []Link{
		{Ref: "a", Path: "/etc/x\ny", Type: "text"},
		{Ref: "a", Path: "/etc/x\ry", Type: "text"},
		{Ref: "a", Path: "/etc/x\x1bcy", Type: "text"},
		{Ref: "a", Path: "/etc/x", Type: "yaml", Key: "a\nb"},
		{Ref: "a", Path: "/etc/x", Type: "yaml", Key: "a\x1bcb"},
	} {
		if err := ValidateLink(link); err == nil {
			t.Errorf("%+v was accepted, so its rule renders across two lines", link)
		}
	}
}

// And the selectors the per-tool recipes use still load, slashes and colons
// included: the check is about the bytes a rule cannot carry.
func TestTheDocumentedSelectorsStillLoad(t *testing.T) {
	for _, link := range []Link{
		{Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml", Type: "yaml",
			Key: "github.com/oauth_token"},
		{Ref: "npm", Path: "/home/op/.npmrc", Type: "ini",
			Key: "//registry.npmjs.org/:_authToken"},
		{Ref: "hub/auth", Path: "/home/op/.docker/config.json", Type: "json",
			Key: `auths/https:\/\/index.docker.io\/v1\//auth`},
	} {
		if err := ValidateLink(link); err != nil {
			t.Errorf("%+v was refused: %v", link, err)
		}
	}
}
