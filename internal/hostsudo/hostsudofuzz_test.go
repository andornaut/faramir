package hostsudo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/layouttest"
)

// spliceRoundTrip writes the block into a stack holding `original`, removes it
// again, and returns what is left plus what the file looked like in between.
func spliceRoundTrip(t *testing.T, original string) (after, withBlock string, wrote error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sudo")
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", layouttest.Layout())
	if err != nil {
		t.Fatal(err)
	}
	fs := hostfs.FS{}
	if _, wrote = SpliceBlock(fs, path, block); wrote != nil {
		return "", "", wrote
	}
	mid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SpliceBlock(fs, path, nil); err != nil {
		return "", string(mid), err
	}
	back, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(back), string(mid), nil
}

// markerLines counts markers that are lines of their own, which is what
// placePamBlock treats as a boundary. Not strings.Count: a marker quoted inside
// somebody's comment is text, not a boundary, and counting it as one would
// assert the opposite of what lineIndex is for.
func markerLines(body, marker string) int {
	n := 0
	for line := range strings.SplitSeq(body, "\n") {
		if line == marker {
			n++
		}
	}
	return n
}

// THE INVARIANT. Putting the block in and taking it out again leaves the file as
// it was, minus any faramir block it already carried. That last clause is the
// whole of the promise: what faramir wrote is faramir's to remove, and
// everything else in a file it does not own has to come back untouched. Checked
// against inputs nobody would write by hand: CRLF, markers that are nearly
// markers, a file that already carries one, no trailing newline.
func FuzzSpliceIsReversible(f *testing.F) {
	for _, seed := range []string{
		layouttest.StockSudoStack,
		"",
		"\n",
		"@include common-auth\n",
		"auth required pam_unix.so", // no trailing newline
		"#%PAM-1.0\r\nauth required pam_unix.so\r\n", // CRLF
		PamBlockBegin + "\n" + PamBlockEnd + "\n",    // an empty block already there
		PamBlockBegin + " \n" + PamBlockEnd + "\n",   // trailing space on a marker
		"# " + PamBlockBegin + "\n",                  // a marker quoted in a comment
		PamBlockBegin + "\nx\n" + PamBlockEnd + "\n" + PamBlockBegin + "\ny\n" + PamBlockEnd + "\n",
		strings.Repeat("auth optional pam_permit.so\n", 50),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, original string) {
		after, withBlock, err := spliceRoundTrip(t, original)
		if err != nil {
			// A refusal is a legitimate outcome (a half-marked file), but it must
			// leave the file alone; the splice checks that itself.
			return
		}
		// What the file held that was not faramir's, which is what has to survive.
		want := string(WithoutBlock([]byte(original)))
		if after != want {
			t.Errorf("round trip did not restore the file.\noriginal: %q\nwant:     %q\nafter:    %q",
				original, want, after)
		}
		// And exactly one block was there in between, counted as boundaries rather
		// than as text: two would be two branches, and the second's jump counts
		// modules that are not below it.
		if n := markerLines(withBlock, PamBlockBegin); n != 1 {
			t.Errorf("counted %d begin marker lines with the block in, want 1:\n%q",
				n, withBlock)
		}
		if n := markerLines(withBlock, PamBlockEnd); n != 1 {
			t.Errorf("counted %d end marker lines with the block in, want 1:\n%q",
				n, withBlock)
		}
	})
}
