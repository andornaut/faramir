package install

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
)

// The comment explaining an entry kind belongs to the kind, not to each entry.
// Rendered inside the loop it is repeated once per entry, which on a host with
// a few dozen blocked paths is most of the file: the operator opens a config
// that is one paragraph said forty times, and the settings that matter are
// spread out of sight between the copies.
func TestAnEntryKindsCommentIsRenderedOnce(t *testing.T) {
	layout := testLayout()
	for i := range 20 {
		layout.Blocked = append(layout.Blocked,
			config.BlockedPath{Path: filepath.Join("/etc/blocked", string(rune('a'+i)))})
		layout.Links = append(layout.Links, config.Link{
			Ref:  "store/ref" + string(rune('a'+i)),
			Path: filepath.Join("/etc/linked", string(rune('a'+i))),
			Type: "text",
		})
	}

	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{
		"Managed by `faramir block`",
		"Managed by `faramir link`",
	} {
		if n := bytes.Count(body, []byte(phrase)); n != 1 {
			t.Errorf("%q appears %d times, want 1", phrase, n)
		}
	}

	// The entries themselves are still one apiece, so hoisting the comment did
	// not hoist the loop with it.
	if n := bytes.Count(body, []byte("[[secret.block]]")); n != len(layout.Blocked) {
		t.Errorf("%d block entries rendered, want %d", n, len(layout.Blocked))
	}
	if n := bytes.Count(body, []byte("[[secret.link]]")); n != len(layout.Links) {
		t.Errorf("%d link entries rendered, want %d", n, len(layout.Links))
	}

	// And it still loads: a comment moved out of a loop moves the lines around
	// the entries with it, which is how a valid file becomes an invalid one.
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the rendered config does not load: %v\n%s", err, body)
	}
}

// A host with neither kind gets neither comment: a heading for a section that
// is not there reads as a section the operator has failed to fill in.
func TestAnEntryKindWithNoEntriesRendersNoComment(t *testing.T) {
	layout := testLayout()
	layout.Blocked = nil
	layout.Links = nil
	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{
		"Managed by `faramir block`",
		"Managed by `faramir link`",
	} {
		if bytes.Contains(body, []byte(phrase)) {
			t.Errorf("%q is rendered for a host that has none", phrase)
		}
	}
}
