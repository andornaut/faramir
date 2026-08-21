package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The pi extension decides for itself which paths its file tools may not name,
// pi having no account-wide rule file for an install to write into. So the rules
// this install renders are only as good as that matcher, and the matcher is
// JavaScript: asserting on the rendered source would say the words are there
// rather than that they refuse anything.
//
// This runs it. The two lists and refusedPath are sliced out of the rendered
// extension and executed by node, unmodified. Skipped where node is absent,
// which is a dev machine without it; CI installs one.
func TestThePiMatcherRefusesALinkedFile(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on this host, so the extension's own matcher went unrun")
	}
	layout := testLayout()
	layout.Links = []config.Link{{Ref: "creds", Path: "/home/op/creds.txt", Type: "text"}}
	layout.Refused = []config.RefusedPath{{Path: "/home/op/keydir"}}
	body, err := renderData("agent/pi/extension.ts.tmpl", pluginData{
		BinDir: "/usr/local/bin", Agent: "pi", Path: "/srv/tree", Layout: layout,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The matcher and what it reads, up to the first thing that needs a runtime.
	const from, to = "const PROTECTED_PATHS", "// runCLI is one faramir invocation"
	start, end := strings.Index(string(body), from), strings.Index(string(body), to)
	if start < 0 || end <= start {
		t.Fatalf("the extension no longer has %q .. %q; this test slices it and "+
			"has to be updated with it", from, to)
	}
	// The slice starts below the imports, and spellings() uses two of them.
	script := "import { homedir } from \"node:os\"\n" +
		"import { normalize } from \"node:path\"\n" +
		string(body[start:end]) + `
const cases = ` + casesJSON + `
let bad = 0
for (const [name, path, want] of cases) {
  const got = refusedPath({ filePath: path }) !== ""
  if (got !== want) { console.log("MISMATCH", name, path, "refused=" + got, "want=" + want); bad++ }
}
console.log(bad === 0 ? "ALL-AS-EXPECTED" : "FAILURES=" + bad)
`
	dir := t.TempDir()
	file := filepath.Join(dir, "matcher.mjs")
	if err := os.WriteFile(file, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, file).CombinedOutput()
	if err != nil {
		t.Fatalf("running the matcher failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ALL-AS-EXPECTED") {
		t.Errorf("the extension's matcher does not refuse what this install names:\n%s", out)
	}
}

// The claims, as the matcher is asked them. A linked path names a file, so a
// list matched only as a directory prefix refuses everything under it and not
// the file itself, which is the one path the entry exists for.
const casesJSON = `[
  ["the linked file itself",       "/home/op/creds.txt",           true],
  ["a file under the refused dir", "/home/op/keydir/private.key",  true],
  ["the refused directory itself", "/home/op/keydir",              true],
  ["this install's own key",       "/opt/conf/age.key",            true],

  ["a dot segment",                "/home/op/./creds.txt",         true],
  ["a parent and back",            "/home/op/../op/creds.txt",     true],
  ["a doubled separator",          "/home/op//creds.txt",          true],
  ["a leading doubled separator",  "//home/op/creds.txt",          true],
  ["dot segments under a dir",     "/home/op/keydir/./private.key", true],

  ["an unrelated file",            "/home/op/notes.txt",           false],
  ["a near miss on the prefix",    "/home/op/creds.txt.bak",       false],
  ["a sibling of the refused dir", "/home/op/keydir-other/id",     false],
  ["a relative path, left alone",  "creds.txt",                    false]
]`
