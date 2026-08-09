package install

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	faramir "github.com/andornaut/faramir"
)

// The installed docs sit the way the checkout does, because everything that
// cites one cites it by the checkout's path.  Asserted against the mapping
// rather than a real install, which writes root-owned files.
func TestTheDocsInstallNestedUnderDocs(t *testing.T) {
	targets, err := docTargets(Layout{DocDir: "/usr/local/share/doc/faramir"})
	if err != nil {
		t.Fatal(err)
	}
	if got := targets["README.md"]; got != "/usr/local/share/doc/faramir/README.md" {
		t.Errorf("README installs to %q, want it at the top of the doc directory", got)
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

// Every link the shipped README makes to a shipped doc resolves from where the
// README lands, that file being the one every unit's Documentation= names.
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
	// The links are written (docs/name.md), so what follows "](docs/" up to the
	// closing paren is the relative path.  Only those: a URL or an anchor is not
	// this test's business.
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
