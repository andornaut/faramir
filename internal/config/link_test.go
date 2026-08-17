package config

import (
	"strings"
	"testing"
)

func TestLinksLoad(t *testing.T) {
	cfg, err := write(t, minimal+`
[secrets]

[[secrets.link]]
ref = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key = "github.com/oauth_token"

[[secrets.link]]
ref = "host/luks"
path = "/home/operator/.private/keyfile"
type = "base64"
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets.Links) != 2 {
		t.Fatalf("links = %v, want two", cfg.Secrets.Links)
	}
	first := cfg.Secrets.Links[0]
	if first.Ref != "gh/token" || first.Type != "yaml" || first.Key != "github.com/oauth_token" {
		t.Errorf("first link = %+v", first)
	}
	if cfg.Secrets.Links[1].Key != "" {
		t.Errorf("a whole-file link carried a key: %+v", cfg.Secrets.Links[1])
	}
}

// The value in a config file that names nothing else: a [secrets] section with
// links and no patterns is a legitimate install.
func TestLinksLoadWithoutPatterns(t *testing.T) {
	cfg, err := write(t, minimal+`
[[secrets.link]]
ref = "gh/token"
path = "/home/operator/.config/gh/hosts.yml"
type = "yaml"
key = "github.com/oauth_token"
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets.Links) != 1 {
		t.Fatalf("links = %v, want one", cfg.Secrets.Links)
	}
	if len(cfg.Secrets.Patterns) != 0 {
		t.Errorf("patterns = %v, want none", cfg.Secrets.Patterns)
	}
}

func TestLinkValidation(t *testing.T) {
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
type = "text"`, "not a name a secret:// reference can carry"},
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
type = "toml"`, `unknown type "toml"`},
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
			_, err := write(t, minimal+"\n[[secrets.link]]"+tc.body+"\n", nil)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// Links are an inventory with one entry per owner, like patterns: a drop-in
// naming one must not discard another's.
func TestLinksAccumulateAcrossDropIns(t *testing.T) {
	cfg, err := write(t, minimal+`
[[secrets.link]]
ref = "base/token"
path = "/x"
type = "text"
`, map[string]string{
		"10-npm.toml": `
[[secrets.link]]
ref = "npm/token"
path = "/y"
type = "ini"
key = "//registry.npmjs.org/:_authToken"
`,
		"20-gh.toml": `
[[secrets.link]]
ref = "gh/token"
path = "/z"
type = "yaml"
key = "github.com/oauth_token"
`})
	if err != nil {
		t.Fatal(err)
	}
	refs := make([]string, 0, len(cfg.Secrets.Links))
	for _, link := range cfg.Secrets.Links {
		refs = append(refs, link.Ref)
	}
	if len(refs) != 3 {
		t.Fatalf("refs = %v, want all three", refs)
	}
}

// Not a duplicate to collapse: which file won would come down to filename
// order, and the ref is the name a caller asks by.
func TestTwoSourcesClaimingOneRefAreRefused(t *testing.T) {
	_, err := write(t, minimal+`
[[secrets.link]]
ref = "gh/token"
path = "/x"
type = "text"
`, map[string]string{
		"10-other.toml": `
[[secrets.link]]
ref = "gh/token"
path = "/y"
type = "text"
`})
	if err == nil {
		t.Fatal("two definitions of one ref were accepted")
	}
	for _, want := range []string{"gh/token", "config.toml", "10-other.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// The same refusal within one file, where filename order is not even the
// tiebreak it could have been.
func TestOneFileClaimingOneRefTwiceIsRefused(t *testing.T) {
	_, err := write(t, minimal+`
[[secrets.link]]
ref = "gh/token"
path = "/x"
type = "text"

[[secrets.link]]
ref = "gh/token"
path = "/y"
type = "text"
`, nil)
	if err == nil {
		t.Fatal("one ref defined twice was accepted")
	}
	if !strings.Contains(err.Error(), "gh/token") {
		t.Errorf("error %q does not name the ref", err)
	}
}

// A scalar where the array of tables goes.  Named rather than ignored: the
// entries would be silently absent.
func TestALinkThatIsNotATableIsRefused(t *testing.T) {
	_, err := write(t, minimal+`
[secrets]
link = "gh/token"
`, nil)
	if err == nil {
		t.Fatal("a scalar link was accepted")
	}
	if !strings.Contains(err.Error(), "[[secrets.link]]") {
		t.Errorf("error %q does not name the shape wanted", err)
	}
}
