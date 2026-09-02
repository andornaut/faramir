package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/hostsudotest"
	"github.com/andornaut/faramir/internal/layouttest"
)

// The block goes in at the top. Anything ahead of it is a module the executor
// meets before the branch is reached, and on a stack whose first auth line is a
// password check that is every escalation refused.
func TestTheBlockGoesAboveEverythingThatAuthenticates(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "sudo"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), hostsudo.PamBlockBegin) {
		t.Errorf("the block is not at the top of the stack:\n%s", body)
	}
	// And the first module the stack reaches is the branch itself, not something
	// the executor would meet before it.
	if first := hostsudo.FirstAuthLine(body); !strings.Contains(first, "pam_succeed_if.so") {
		t.Errorf("the first auth line is not the branch: %q", first)
	}
	// And what the file already said is still there, all of it.
	if !strings.Contains(string(body), layouttest.StockSudoStack) {
		t.Errorf("the distribution's own stack did not survive the splice:\n%s", body)
	}
}

// Both stacks, because the service name is the launch type: a host covered for
// `sudo` and not for `sudo -i` is one where a login shell escalation meets the
// password check instead of the question.
func TestBothSharedStacksGetTheBranch(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sudo", "sudo-i"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "pam_exec.so quiet seteuid "+run.layout.PamHelper()) {
			t.Errorf("%s does not ask the broker:\n%s", name, body)
		}
	}
}

// Written twice is written once: a re-run replaces what the last one left
// rather than stacking a second branch, which would be two modules where the
// jump counts one.
func TestWritingTheBlockTwiceLeavesOne(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "sudo"))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := run.writeSudoPamBlock()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a second write reported a change with nothing to change")
	}
	second, err := os.ReadFile(filepath.Join(dir, "sudo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("a re-run rewrote the stack:\n%s", second)
	}
	if n := strings.Count(string(second), hostsudo.PamBlockBegin); n != 1 {
		t.Errorf("counted %d blocks, want 1:\n%s", n, second)
	}
}

// A revoke takes out the branch and nothing else. The rest of the file is the
// distribution's, and an uninstall that trimmed a line of it would be one that
// changed how every account on the host authenticates.
func TestRemovingTheBlockLeavesTheStackAsItWas(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	if _, err := hostsudo.RemoveBlock(run.fs); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sudo", "sudo-i"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != layouttest.StockSudoStack {
			t.Errorf("%s is not what it was before the block went in:\n%s", name, body)
		}
	}
	// And a second removal is not an error on a host that has none.
	if changed, err := hostsudo.RemoveBlock(run.fs); err != nil || changed {
		t.Errorf("removing an absent block reported changed=%v err=%v", changed, err)
	}
}

// One marker without the other is refused rather than guessed at. Where the
// block starts or stops cannot be read off such a file, and a wrong guess
// rewrites the stack that decides every account's sudo.
func TestAHalfMarkedStackIsRefused(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	path := filepath.Join(dir, "sudo")
	if err := os.WriteFile(path, []byte(hostsudo.PamBlockBegin+"\n"+layouttest.StockSudoStack), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{layout: testLayout()}
	_, err := run.writeSudoPamBlock()
	if err == nil {
		t.Fatal("a stack carrying one marker was written to anyway")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the refusal does not name the file: %v", err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(body), layouttest.StockSudoStack) {
		t.Errorf("the stack was rewritten by a run that refused:\n%s", body)
	}
}

// An install that does not grant sudo takes the branch out, whatever the host's
// sudo is now: a re-run without --allow-sudo removes the service the branch
// names, and a branch left pointing at a file that is gone sends the executor to
// /etc/pam.d/other.
func TestRevokingTakesTheBranchOut(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	hostsudotest.PinSudo(t, false)
	run := &runner{layout: testLayout()}
	// The revoke removes the environment file with the rest of the grant, so the
	// layout points at this test's directory rather than the install's.
	run.layout.LibexecDir = dir
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	run.layout.AllowSudo = false
	if err := run.revokeSudoGrant(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "sudo"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), hostsudo.PamBlockBegin) {
		t.Errorf("the branch outlived the grant:\n%s", body)
	}
}

// And no service file is written where nothing can be sent to it: sudo-rs
// reaches the service named `sudo` and nothing a caller may name, so one beside
// the block would be a stack nothing reads.
func TestNoServiceFileIsWrittenUnderSudoRs(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	hostsudotest.PinSudo(t, true)
	run := &runner{layout: testLayout()}
	run.layout.SudoRs = true
	run.layout.LibexecDir = dir
	// One left by an install made when this host's sudo was the original.
	if err := os.WriteFile(hostlayout.PamServiceFile, []byte("auth required pam_permit.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	if _, err := run.syncPamService(); err != nil {
		t.Fatal(err)
	}
	if hostfs.Exists(hostlayout.PamServiceFile) {
		t.Errorf("%s is still there on a sudo-rs host, where nothing reads it",
			hostlayout.PamServiceFile)
	}
}

// A block that ended up below the line that authenticates is moved back to the
// top rather than rewritten where it lies. Left there it is a branch nobody
// reaches: the executor meets the password check first and every escalation
// fails, on a host doctor would otherwise call well.
func TestABlockBelowTheAuthLineIsHoistedBack(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	path := filepath.Join(dir, "sudo")
	run := &runner{layout: testLayout()}
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", run.layout)
	if err != nil {
		t.Fatal(err)
	}
	// The shape a conffile merge or a hand edit leaves.
	if err := os.WriteFile(path, append([]byte(layouttest.StockSudoStack), block...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), hostsudo.PamBlockBegin) {
		t.Errorf("the block was left below what authenticates:\n%s", body)
	}
	if n := strings.Count(string(body), hostsudo.PamBlockBegin); n != 1 {
		t.Errorf("counted %d blocks, want 1", n)
	}
	// And doctor agrees, which it did not before: the stock stack authenticates
	// with `@include common-auth` and has no line beginning `auth` at all.
	hostsudotest.PinSudo(t, true)
	if problem := hostsudo.BranchProblem(run.layout.ExecUser, run.layout.PamHelper()); problem != "" {
		t.Errorf("the hoisted block still reads as misplaced: %s", problem)
	}
	// The same file with the block put back underneath is what must fail.
	if err := os.WriteFile(path, append([]byte(layouttest.StockSudoStack), block...), 0o644); err != nil {
		t.Fatal(err)
	}
	problem := hostsudo.BranchProblem(run.layout.ExecUser, run.layout.PamHelper())
	if problem == "" {
		t.Error("a block sitting below `@include common-auth` was reported as fine")
	}
}

// The jump is checked against what is on the host, not only against what was
// rendered: a block edited by hand to add a module is one whose branch now lands
// inside it, and that authenticates every other account for free.
func TestAJumpThatNoLongerClearsTheBlockIsReported(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	hostsudotest.PinSudo(t, true)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sudo")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// One more module inside the block, the jump left as it was.
	edited := strings.Replace(string(body), hostsudo.PamBlockEnd,
		"auth optional pam_permit.so\n"+hostsudo.PamBlockEnd, 1)
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	problem := hostsudo.BranchProblem(run.layout.ExecUser, run.layout.PamHelper())
	if problem == "" {
		t.Fatal("a block with a module the jump does not clear was reported as fine")
	}
	if !strings.Contains(problem, "without a password") {
		t.Errorf("the failure does not say what it costs: %s", problem)
	}
}

// The broker's own check has to find the stack wherever it is. On a sudo-rs host
// there is no service file at all, and a check that stats one reports a host
// that works as one that cannot escalate -- which fails `init` at the validate
// step, after the grant is already on disk.
func TestTheBrokerFindsTheStackOnEitherArrangement(t *testing.T) {
	dir := layouttest.SudoStacks(t)

	if _, err := escalation.StackFile(dir, hostlayout.PamServiceName); err == nil {
		t.Error("a host with neither arrangement reported a stack")
	}
	// The sudo-rs arrangement: a block, and no service file.
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	stack, err := escalation.StackFile(dir, hostlayout.PamServiceName)
	if err != nil {
		t.Fatalf("the block was not recognised as the stack: %v", err)
	}
	if stack != filepath.Join(dir, "sudo") {
		t.Errorf("found %q, want the shared stack", stack)
	}
	// And the classic one: a service file, which wins.
	if err := os.WriteFile(filepath.Join(dir, hostlayout.PamServiceName),
		[]byte("auth requisite pam_exec.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if stack, err = escalation.StackFile(dir, hostlayout.PamServiceName); err != nil ||
		stack != filepath.Join(dir, hostlayout.PamServiceName) {
		t.Errorf("found %q (%v), want the service file", stack, err)
	}
}

// A shared stack that is a symlink to the other one is how some distributions
// ship the login case. The block lands on the target through the real file, so
// the link is already covered and refusing the install over it would fail a host
// that works.
func TestASharedStackLinkedToTheOtherIsAlreadyCovered(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	link := filepath.Join(dir, "sudo-i")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "sudo"), link); err != nil {
		t.Fatal(err)
	}
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatalf("a sudo-i linked to sudo failed the install: %v", err)
	}
	body, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(body), hostsudo.PamBlockBegin); n != 1 {
		t.Errorf("counted %d blocks through the link, want 1:\n%s", n, body)
	}
	// And the link is still a link: writing through it would have replaced it.
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the splice replaced the symlink with a file")
	}
	// A link to somewhere else entirely is still refused, that being a write
	// landing outside the two files faramir means to touch.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "somewhere-else")
	if err := os.WriteFile(outside, []byte(layouttest.StockSudoStack), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err == nil {
		t.Error("a stack linked outside the shared pair was written through")
	}
}

// A stack carrying two blocks is collapsed to one. Nothing faramir writes makes
// that state, but a conffile merge or a hand edit can, and taking out only the
// block this run could see left the other there through every re-run and every
// revoke, with nothing able to remove it.
func TestASecondBlockIsNotLeftBehind(t *testing.T) {
	dir := layouttest.SudoStacks(t)
	path := filepath.Join(dir, "sudo")
	run := &runner{layout: testLayout()}
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", run.layout)
	if err != nil {
		t.Fatal(err)
	}
	doubled := append(append(append([]byte{}, block...), block...), []byte(layouttest.StockSudoStack)...)
	if err := os.WriteFile(path, doubled, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(body), hostsudo.PamBlockBegin); n != 1 {
		t.Errorf("a re-run left %d blocks, want 1:\n%s", n, body)
	}
	// And a revoke takes the file back to what the distribution put there.
	if err := os.WriteFile(path, doubled, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hostsudo.RemoveBlock(run.fs); err != nil {
		t.Fatal(err)
	}
	if body, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	if string(body) != layouttest.StockSudoStack {
		t.Errorf("a revoke left a block behind:\n%s", body)
	}
}
