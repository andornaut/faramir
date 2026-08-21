package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// What refuses a path, which is the question the report is built on: an entry
// this install declares, a pattern it declares, or a directory it installed.
func TestRefusedByAnswersForEveryForm(t *testing.T) {
	layout := Layout{
		ConfigDir:  "/etc/faramir",
		LogDir:     "/var/log/faramir",
		LibexecDir: "/usr/local/libexec/faramir",
		Refused: []config.RefusedPath{
			{Path: "/etc/luks/volume.key"},
			{Name: "*.pem"},
			{Name: ".ssh/"},
		},
		Links: []config.Link{{Ref: "npm", Path: "/home/op/.npmrc"}},
	}
	for path, want := range map[string]string{
		"/etc/faramir/age.key":       "/etc/faramir",
		"/etc/faramir/secrets/a.yml": "/etc/faramir",
		"/var/log/faramir/audit.log": "/var/log/faramir",
		"/etc/luks/volume.key":       "/etc/luks/volume.key",
		"/home/op/.npmrc":            "/home/op/.npmrc",
		"/srv/certs/server.pem":      ".pem",
		"/home/op/.ssh/id_rsa":       ".ssh/",
	} {
		got, covered := RefusedBy(layout, path)
		if !covered {
			t.Errorf("%s is refused by nothing, want %s", path, want)
			continue
		}
		if got != want {
			t.Errorf("%s is refused by %q, want %q", path, got, want)
		}
	}
	for _, path := range []string{
		"/home/op/.aws/credentials",
		"/srv/app/main.go",
		"/etc/faramir-other/age.key",
	} {
		if by, covered := RefusedBy(layout, path); covered {
			t.Errorf("%s was read as refused by %q", path, by)
		}
	}
}

// The report itself: what is in the agent's home, refused by nothing, and worth
// telling the operator about. A warning rather than a failure, a host that has
// decided what to refuse not being a broken one.
func TestUnrefusedCredentialsNamesWhatIsThere(t *testing.T) {
	home := t.TempDir()
	for _, rel := range []string{".ssh/id_ed25519", ".aws/credentials", ".npmrc"} {
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An ordinary file of the same shape, which must not be named.
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	layout := Layout{ConfigDir: "/etc/faramir"}
	var found []string
	for _, rel := range wellKnownCredentials {
		path := filepath.Join(home, rel)
		if !exists(path) {
			continue
		}
		if _, covered := RefusedBy(layout, path); covered {
			continue
		}
		found = append(found, path)
	}
	if len(found) != 3 {
		t.Fatalf("found %v, want the three that are there", found)
	}
	// The command it offers has to be one the operator can paste, and one that
	// covers the next machine as well: a name rather than this home's path.
	suggestion := suggestFor(found)
	// The directory that makes a file a credential is kept: "credentials" alone
	// refuses every file of that name, and ".ssh/id_ed25519" says what is meant.
	for _, want := range []string{
		"--name .ssh/id_ed25519", "--name .aws/credentials", "--name .npmrc",
	} {
		if !strings.Contains(suggestion, want) {
			t.Errorf("the suggestion does not carry %q: %s", want, suggestion)
		}
	}
	if strings.Contains(suggestion, home) {
		t.Errorf("the suggestion names this machine's own paths: %s", suggestion)
	}
}

// And nothing is named once it is declared, which is what makes the check go
// quiet after the operator acts on it rather than nagging for ever.
func TestUnrefusedCredentialsGoesQuietOnceDeclared(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh/id_rsa")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	layout := Layout{ConfigDir: "/etc/faramir", Refused: []config.RefusedPath{{Name: "id_rsa"}}}
	if by, covered := RefusedBy(layout, path); !covered {
		t.Error("a declared name does not cover the file it names")
	} else if by != "id_rsa" {
		t.Errorf("covered by %q, want the declared name", by)
	}
}
