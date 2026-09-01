package hostsudo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/layouttest"
)

// A marker quoted inside somebody's comment is not a boundary. Matching it as a
// substring would let a line about faramir in an operator's own note decide
// where the block ends.
func TestAQuotedMarkerIsNotABoundary(t *testing.T) {
	body := []byte("# see '" + PamBlockBegin + "' below\n" + layouttest.StockSudoStack)
	if _, _, found, err := PlaceBlock(body); found || err != nil {
		t.Errorf("a quoted marker was read as a block: found=%v err=%v", found, err)
	}
}

// A splice that changed anything outside the block is undone rather than left.
// This is a file the distribution owns and every account's sudo reads, so a
// write that came out wrong is a host nobody can sudo on, and an install that
// noticed and carried on would be one that broke a machine quietly.
func TestASpliceThatDamagesTheStackIsPutBack(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	path := filepath.Join(dir, "sudo")
	// A block whose end marker is missing: what lands parses as half-marked, which
	// is the shape spliceProblem refuses.
	if problem := SpliceProblem(path, []byte(layouttest.StockSudoStack), []byte(PamBlockBegin+"\n")); problem == "" {
		t.Error("a block with no end marker was accepted")
	}
	// And the claim itself, against what is actually on disk: everything outside
	// the block has to come back unchanged.
	before := []byte(layouttest.StockSudoStack)
	if err := os.WriteFile(path, []byte("something else entirely\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if problem := SpliceProblem(path, before, nil); problem == "" {
		t.Error("a stack rewritten out from under the splice was accepted")
	}
}

// The block is cut out of both sides before they are compared, or a run that
// replaced an older block would read as one that ate the file.
func TestTheComparisonIgnoresTheBlockItself(t *testing.T) {
	withBlock := []byte(PamBlockBegin + "\nauth optional pam_permit.so\n" + PamBlockEnd + "\n" + layouttest.StockSudoStack)
	if got := string(WithoutBlock(withBlock)); got != layouttest.StockSudoStack {
		t.Errorf("cutting the block out left %q, want the stock stack", got)
	}
	if got := string(WithoutBlock([]byte(layouttest.StockSudoStack))); got != layouttest.StockSudoStack {
		t.Errorf("a stack with no block was changed: %q", got)
	}
}

// A second factor somebody put on this host's sudo is named rather than stepped
// over in silence: the branch goes above it, so the executor reaches root
// without meeting it. An `include` of the distribution's shared stack is what a
// stock file says and draws nothing.
func TestAThirdPartyAuthModuleIsNamed(t *testing.T) {
	for body, want := range map[string]string{
		layouttest.StockSudoStack:                                                        "",
		"auth include system-auth\n@include common-account\n":                            "",
		"auth substack password-auth\n":                                                  "",
		"# auth required pam_duo.so\n@include common-auth\n":                             "",
		"auth required pam_duo.so\n@include common-auth\n":                               "auth required pam_duo.so",
		layouttest.StockSudoStack + "auth required pam_google_authenticator.so nullok\n": "auth required pam_google_authenticator.so nullok",
	} {
		if got := ForeignAuthModule([]byte(body)); got != want {
			t.Errorf("got %q, want %q, for:\n%s", got, want, body)
		}
	}
}

// THE ONE THAT MATTERS. The branch's jump has to skip every faramir module that
// follows it and land on the stack this file already had. One short and it lands
// on faramir's own `sufficient pam_permit`, which authenticates EVERY OTHER
// ACCOUNT ON THE HOST with no password at all.
//
// Counted off the rendered block rather than asserted as a literal, so a line
// added or removed below the branch fails here instead of on a host.
func TestTheBranchSkipsEveryModuleItPutThere(t *testing.T) {
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	var branch string
	after := 0
	for line := range strings.Lines(layouttest.Uncommented(string(block))) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "auth") {
			continue
		}
		if branch == "" {
			branch = line
			continue
		}
		after++
	}
	if branch == "" {
		t.Fatal("the block has no auth line at all")
	}
	if !strings.Contains(branch, "pam_succeed_if.so") {
		t.Fatalf("the first auth line is not the account branch: %q", branch)
	}
	want := fmt.Sprintf("default=%d", after)
	if !strings.Contains(branch, want) {
		t.Errorf("the branch is %q but %d module(s) follow it in the block: it must "+
			"say %q, or an account that is not the executor lands on one of them",
			branch, after, want)
	}
	// And the module it must never land on is the last of them.
	lines := strings.Split(strings.TrimSpace(layouttest.Uncommented(string(block))), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); !strings.Contains(last, "pam_permit.so") ||
		!strings.Contains(last, "sufficient") {
		t.Errorf("the block does not end with `sufficient pam_permit.so`, so the "+
			"count above is measuring something else: %q", last)
	}
}

// The block is the whole stack on a sudo-rs host, so everything pamStackProblem
// asserts about a service file has to hold of it too: the helper is requisite,
// runs with seteuid, and is faramir's own.
func TestTheBlockIsAStackPamStackProblemAccepts(t *testing.T) {
	layout := testLayout()
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if problem := StackProblem(string(block), layout.PamHelper()); problem != "" {
		t.Errorf("the rendered block is not a stack that gates: %s", problem)
	}
}

// A half-marked stack is not a stack the broker may answer for: it cannot tell
// what the block is, and reporting a host as able to escalate on the strength of
// a stray marker is worse than reporting it as broken.
func TestAStrayMarkerIsNotAStack(t *testing.T) {
	if escalation.HasBlock(escalation.BlockBegin + "\nauth required pam_permit.so\n") {
		t.Error("a begin marker with no end was read as a block")
	}
	if escalation.HasBlock("# see '" + escalation.BlockBegin + "' in the docs\n") {
		t.Error("a marker quoted in a comment was read as a block")
	}
	if !escalation.HasBlock(escalation.BlockBegin + "\nauth optional pam_permit.so\n" +
		escalation.BlockEnd + "\n") {
		t.Error("a whole block was not recognised")
	}
}
