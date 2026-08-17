package secretlink

import (
	"bytes"
	"os"
	"path/filepath"
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
	_, err := Extract("toml", "k", []byte("k=v"))
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
		KindJSON: true, KindYAML: true, KindINI: true,
	} {
		if got := NeedsKey(kind); got != want {
			t.Errorf("NeedsKey(%q) = %v, want %v", kind, got, want)
		}
	}
}
