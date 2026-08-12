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

// A dashed aside reads as something nobody here typed, and one arrives whenever
// a paragraph is written somewhere that substitutes the character.  The prose
// uses a comma, a colon or another sentence instead, so the character itself is
// the check: what it would have meant is always sayable another way.
//
// Both dashes, not only the em: a range reads as well written out, and the one
// place a glyph is wanted is `doctor`'s status column, which is output.
//
// Over the embedded assets, which is the prose that ships.  Go comments spell
// the same aside "--", and are not reached from here.
func TestTheShippedProseHasNoDashedAsides(t *testing.T) {
	// Spelled by code point, or this file is its own first failure.
	dashes := map[string]rune{"em dash": 0x2014, "en dash": 0x2013}
	err := fs.WalkDir(faramir.Assets, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		body, err := faramir.Assets.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(body), "\n") {
			for name, dash := range dashes {
				if strings.ContainsRune(line, dash) {
					t.Errorf("%s:%d has an %s; use a comma, a colon or a full stop:\n  %s",
						path, i+1, name, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
