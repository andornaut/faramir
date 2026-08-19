package secretlink

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestExtractText(t *testing.T) {
	for name, tc := range map[string]struct {
		data string
		want string
	}{
		"trailing newline": {"gho_token\n", "gho_token"},
		"no newline":       {"gho_token", "gho_token"},
		"surrounding":      {"  gho_token \n\n", "gho_token"},
		"inner space kept": {"two words\n", "two words"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Extract(KindText, "", []byte(tc.data))
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A keyfile is random bytes, which cannot be an environment variable or be
// matched in output.  The refusal has to name the way out, or an operator whose
// link is refused has nothing to do about it.
func TestExtractTextRefusesBinary(t *testing.T) {
	_, err := Extract(KindText, "", []byte{0xff, 0xfe, 0x00, 0x01})
	if err == nil {
		t.Fatal("binary accepted as text")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("refusal does not name the alternative: %v", err)
	}
}

func TestExtractBase64(t *testing.T) {
	got, err := Extract(KindBase64, "", []byte{0x00, 0x01, 0xff})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got != "AAH/" {
		t.Errorf("got %q, want %q", got, "AAH/")
	}
}

func TestExtractEmptyIsRefused(t *testing.T) {
	for _, kind := range []string{KindText, KindBase64} {
		if _, err := Extract(kind, "", nil); err == nil {
			t.Errorf("%s: empty file accepted", kind)
		}
	}
}

func TestExtractJSON(t *testing.T) {
	// The shape ~/.docker/config.json takes.
	data := []byte(`{"auths":{"ghcr.io":{"auth":"c2VjcmV0"}},"count":3,"on":true}`)
	for name, tc := range map[string]struct {
		key     string
		want    string
		wantErr string
	}{
		"nested":     {key: "auths/ghcr.io/auth", want: "c2VjcmV0"},
		"number":     {key: "count", want: "3"},
		"missing":    {key: "auths/docker.io/auth", wantErr: "has no auths/docker.io"},
		"not scalar": {key: "auths", wantErr: "not a value"},
		"boolean":    {key: "on", wantErr: "never a secret"},
		"through a leaf": {key: "count/deeper",
			wantErr: "has no count/deeper: count is not a table or a list"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Extract(KindJSON, tc.key, data)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got (%q, %v), want an error containing %q", got, err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("Extract: %v", err)
			case got != tc.want:
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractJSONList(t *testing.T) {
	got, err := Extract(KindJSON, "keys/1", []byte(`{"keys":["first","second"]}`))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got != "second" {
		t.Errorf("got %q, want %q", got, "second")
	}
	if _, err := Extract(KindJSON, "keys/9", []byte(`{"keys":["first"]}`)); err == nil {
		t.Error("an index past the end was accepted")
	}
}

// The shape ~/.config/gh/hosts.yml takes, which is what the first link reads.
func TestExtractYAML(t *testing.T) {
	data := []byte("github.com:\n    oauth_token: gho_example\n    user: someone\n" +
		"    git_protocol: ssh\n")
	got, err := Extract(KindYAML, "github.com/oauth_token", data)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got != "gho_example" {
		t.Errorf("got %q, want %q", got, "gho_example")
	}
	if _, err := Extract(KindYAML, "github.com/nothing", data); err == nil {
		t.Error("a selector naming nothing was accepted")
	}
}

// The shape ~/.npmrc takes: a key holding slashes and a colon, which is why the
// selector is the whole key rather than a path through it.
func TestExtractINI(t *testing.T) {
	data := []byte("; a comment\n//registry.npmjs.org/:_authToken=npm_example\n" +
		"[scoped]\ntoken = \"quoted\"\nblank=\n")
	for name, tc := range map[string]struct {
		key     string
		want    string
		wantErr string
	}{
		"npm token":                 {key: "//registry.npmjs.org/:_authToken", want: "npm_example"},
		"in a section":              {key: "scoped/token", want: "quoted"},
		"missing":                   {key: "absent", wantErr: "has no absent"},
		"empty":                     {key: "scoped/blank", wantErr: "is empty"},
		"section not searched flat": {key: "token", wantErr: "has no token"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Extract(KindINI, tc.key, data)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got (%q, %v), want an error containing %q", got, err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("Extract: %v", err)
			case got != tc.want:
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractUnknownKindNamesTheKnownOnes(t *testing.T) {
	_, err := Extract("xml", "k", []byte("<k>v</k>"))
	if err == nil {
		t.Fatal("unknown type accepted")
	}
	for _, kind := range Kinds() {
		if !strings.Contains(err.Error(), kind) {
			t.Errorf("refusal does not name %q: %v", kind, err)
		}
	}
}

// Every error reaches the daemon log and `--check`, so none of them may quote
// the file.  A decoder's own message often does, which is why they are replaced
// rather than wrapped.
func TestErrorsCarryNoFileContent(t *testing.T) {
	const value = "SUPERSECRETVALUE"
	cases := []struct {
		kind, key string
		data      string
	}{
		{KindJSON, "k", `{"k": "` + value + `"`},        // truncated JSON
		{KindYAML, "k", "k: [" + value},                 // truncated YAML
		{KindJSON, "absent", `{"k":"` + value + `"}`},   // selector misses
		{KindYAML, "absent", "k: " + value + "\n"},      // selector misses
		{KindINI, "absent", "k=" + value + "\n"},        // selector misses
		{KindJSON, "k/deeper", `{"k":"` + value + `"}`}, // walks through a leaf
		{"unknown", "k", "k=" + value},                  // unknown type
	}
	for _, tc := range cases {
		_, err := Extract(tc.kind, tc.key, []byte(tc.data))
		if err == nil {
			t.Errorf("%s/%s: no error", tc.kind, tc.key)
			continue
		}
		if strings.Contains(err.Error(), value) {
			t.Errorf("%s/%s: error quotes the file: %v", tc.kind, tc.key, err)
		}
	}
}

func TestReadRefusesAnOversizeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, KindText, ""); err == nil {
		t.Fatal("an oversize file was read")
	}
}

func TestReadReportsAMissingFile(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "absent"), KindText, ""); !os.IsNotExist(err) {
		t.Fatalf("want a not-exist error, got %v", err)
	}
}

func TestNeedsKey(t *testing.T) {
	for kind, want := range map[string]bool{
		KindText: false, KindBase64: false,
		KindJSON: true, KindYAML: true, KindTOML: true, KindINI: true,
	} {
		if !slices.Contains(Kinds(), kind) {
			t.Errorf("%q is not a known kind, so this row asserts nothing", kind)
		}
		if got := NeedsKey(kind); got != want {
			t.Errorf("NeedsKey(%q) = %v, want %v", kind, got, want)
		}
	}
}

// A key holding a slash is what a container registry file names its entries
// by, so a selector has to be able to say "this one key" rather than walking
// levels that are not there.
func TestASelectorNamesAKeyHoldingASlash(t *testing.T) {
	body := []byte(`{"auths": {"https://index.docker.io/v1/": {"auth": "c2VjcmV0"}}}`)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path, KindJSON, `auths/https:\/\/index.docker.io\/v1\//auth`)
	if err != nil {
		t.Fatalf("escaped selector did not read: %v", err)
	}
	if got != "c2VjcmV0" {
		t.Errorf("value = %q, want the auth entry", got)
	}
	// Unescaped, the same text walks levels that are not there rather than
	// silently selecting something else.
	if _, err := Read(path, KindJSON, "auths/https://index.docker.io/v1//auth"); err == nil {
		t.Error("an unescaped slash selected something; it names no such path")
	}
}

// The listing is copied into a --key, so every name it offers has to select.
// Enumerating and selecting are two spellings of one thing and drift silently.
func TestEveryKeyOfferedCanBeSelected(t *testing.T) {
	for _, tc := range []struct{ kind, body string }{
		// The trailing-backslash key is the one that pins escaping the escape: a
		// segment ending in "\\" runs into the separator after it, and unescaped
		// the two read as one escaped slash and the walk loses a level.
		{KindJSON, `{"auths": {"ghcr.io": {"auth": "a"}, "https://x.io/v1/": {"auth": "b"}},
		             "back\\slash": "c", "trailing\\": {"leaf": "e"}, "list": ["d"]}`},
		{KindYAML, "plain: a\n\"with/slash\": b\n\"back\\\\slash\": c\nlist:\n  - d\n"},
		{KindTOML, "plain = \"a\"\n\"with/slash\" = \"b\"\n[table]\nkey = \"c\"\n"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file."+tc.kind)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			keys, err := KeysIn(path, tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) == 0 {
				t.Fatal("no keys offered, so this asserts nothing")
			}
			for _, key := range keys {
				if _, err := Read(path, tc.kind, key); err != nil {
					t.Errorf("offered %q, which does not select: %v", key, err)
				}
			}
		})
	}
}

// TOML is the fourth structured kind, and it goes through the same selector as
// the other three rather than a spelling of its own.
func TestTOMLSelectsLikeTheOthers(t *testing.T) {
	body := "token = \"top-level\"\n\n[registry.\"ghcr.io\"]\ntoken = \"nested\"\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, want string }{
		{"token", "top-level"},
		{"registry/ghcr.io/token", "nested"},
	} {
		got, err := Read(path, KindTOML, tc.key)
		if err != nil {
			t.Fatalf("%s: %v", tc.key, err)
		}
		if got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	if _, err := Read(path, KindTOML, "nope"); err == nil {
		t.Error("a key that is not there was read")
	}
}

// The error names the part of the selector that was reached, and it is spelled
// the way the selector was: cut on a raw "/" it would divide a key holding one
// and name a parent nobody wrote.
func TestAnErrorNamesTheParentInTheSelectorsOwnSpelling(t *testing.T) {
	_, err := Extract(KindJSON, `a/b\/c`, []byte(`{"a":"leaf"}`))
	if err == nil {
		t.Fatal("walking through a leaf was accepted")
	}
	if !strings.Contains(err.Error(), "a is not a table or a list") {
		t.Errorf("error names the wrong parent: %v", err)
	}
}

// A slash in a section or a key can make two different entries compose to one
// selector.  That is this package's own ambiguity rather than the file's, so it
// is refused: picking the first would be picking which credential to inject,
// and the one not picked is then absent from the redactor and comes back in the
// clear if anything prints it.
func TestAnAmbiguousINISelectorIsRefused(t *testing.T) {
	body := []byte("a/b/c = sectionless\n\n[a]\nb/c = in-a\n\n[a/b]\nc = in-ab\n")
	_, err := Extract(KindINI, "a/b/c", body)
	if err == nil {
		t.Fatal("an ambiguous selector was answered rather than refused")
	}
	for _, want := range []string{"a/b/c outside any section", "b/c under [a]", "c under [a/b]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	// Naming only one of them is unambiguous and still reads.
	got, err := Extract(KindINI, "a/b", []byte("[a]\nb = plain\n"))
	if err != nil || got != "plain" {
		t.Errorf("an unambiguous section key stopped reading: %q %v", got, err)
	}
}

// The file holding one key twice is the file's own ambiguity, and INI's answer
// is first wins.  That is not the case above and must not be swept into it.
func TestADuplicateINIKeyStillTakesTheFirst(t *testing.T) {
	for name, body := range map[string]string{
		"in a section": "[s]\nk = first\nk = second\n",
		"at top level": "k = first\nk = second\n",
	} {
		key := "k"
		if strings.Contains(body, "[s]") {
			key = "s/k"
		}
		t.Run(name, func(t *testing.T) {
			got, err := Extract(KindINI, key, []byte(body))
			if err != nil {
				t.Fatalf("a duplicate key was refused: %v", err)
			}
			if got != "first" {
				t.Errorf("got %q, want the first", got)
			}
		})
	}
}
