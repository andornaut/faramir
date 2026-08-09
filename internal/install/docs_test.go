package install

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	faramir "github.com/andornaut/faramir"
)

// The installed docs sit the way the checkout does, everything citing one by
// the checkout's path.  Against the mapping, a real install writing root-owned
// files.
func TestTheDocsInstallNestedUnderDocs(t *testing.T) {
	targets, err := docTargets(Layout{DocDir: "/usr/local/share/doc/faramir"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README.md", "LICENSE"} {
		want := "/usr/local/share/doc/faramir/" + name
		if got := targets[name]; got != want {
			t.Errorf("%s installs to %q, want it at the top of the doc directory as %q",
				name, got, want)
		}
	}
	entries, err := fs.ReadDir(faramir.Assets, "docs")
	if err != nil {
		t.Fatal(err)
	}
	shipped := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		shipped++
		want := "/usr/local/share/doc/faramir/docs/" + entry.Name()
		if got := targets["docs/"+entry.Name()]; got != want {
			t.Errorf("%s installs to %q, want %q", entry.Name(), got, want)
		}
	}
	if shipped == 0 {
		t.Fatal("no docs are embedded, so this asserts nothing")
	}
}

// Every link the shipped README makes resolves from where it lands, that being
// what every unit's Documentation= names.
func TestTheInstalledReadmeLinksResolve(t *testing.T) {
	layout := Layout{DocDir: "/usr/local/share/doc/faramir"}
	targets, err := docTargets(layout)
	if err != nil {
		t.Fatal(err)
	}
	body, err := fs.ReadFile(faramir.Assets, "README.md")
	if err != nil {
		t.Fatal(err)
	}
	// What follows "](docs/" up to the closing paren.  Only those: a URL or an
	// anchor is not this test's business.
	checked := 0
	for _, part := range strings.Split(string(body), "](docs/")[1:] {
		link, _, found := strings.Cut(part, ")")
		if !found || !strings.HasSuffix(link, ".md") {
			continue
		}
		checked++
		// Where the link points, resolved from the installed README.
		want := filepath.Join(layout.DocDir, "docs", link)
		if targets["docs/"+link] != want {
			t.Errorf("README links docs/%s, which installs to %q rather than %q",
				link, targets["docs/"+link], want)
		}
	}
	if checked == 0 {
		t.Fatal("no doc links found in the README, so this asserts nothing")
	}
}
