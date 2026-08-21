package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
)

// pinSudo answers the probe for a test, so which arrangement is written or
// diagnosed is the test's to choose rather than the machine's.
func pinSudo(t *testing.T, rs bool) {
	t.Helper()
	original := sudoRsProbe
	sudoRsProbe = func() bool { return rs }
	t.Cleanup(func() { sudoRsProbe = original })
}

// stockSudoStack is /etc/pam.d/sudo as a distribution ships it: a session
// preamble and the includes that authenticate everybody.
const stockSudoStack = `#%PAM-1.0

session    required   pam_limits.so

@include common-auth
@include common-account
@include common-session-noninteractive
`

// sudoStacks writes both shared stacks into a redirected /etc/pam.d and returns
// the directory.
//
// It redirects the grant and the service file with them. This machine may be a
// granting host: a test that reached the real paths would be one that revoked
// the install it was running on.
func sudoStacks(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pam, grant, service := pamDir, sudoersFile, pamServiceFile
	pamDir = dir
	sudoersFile = filepath.Join(dir, "sudoers-faramir")
	pamServiceFile = filepath.Join(dir, pamServiceName)
	t.Cleanup(func() { pamDir, sudoersFile, pamServiceFile = pam, grant, service })
	for _, name := range []string{"sudo", "sudo-i"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(stockSudoStack), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The block goes in at the top. Anything ahead of it is a module the executor
// meets before the branch is reached, and on a stack whose first auth line is a
// password check that is every escalation refused.
func TestTheBlockGoesAboveEverythingThatAuthenticates(t *testing.T) {
	dir := sudoStacks(t)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "sudo"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), pamBlockBegin) {
		t.Errorf("the block is not at the top of the stack:\n%s", body)
	}
	// And the first module the stack reaches is the branch itself, not something
	// the executor would meet before it.
	if first := firstAuthLine(body); !strings.Contains(first, "pam_succeed_if.so") {
		t.Errorf("the first auth line is not the branch: %q", first)
	}
	// And what the file already said is still there, all of it.
	if !strings.Contains(string(body), stockSudoStack) {
		t.Errorf("the distribution's own stack did not survive the splice:\n%s", body)
	}
}

// Both stacks, because the service name is the launch type: a host covered for
// `sudo` and not for `sudo -i` is one where a login shell escalation meets the
// password check instead of the question.
func TestBothSharedStacksGetTheBranch(t *testing.T) {
	dir := sudoStacks(t)
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
	dir := sudoStacks(t)
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
	if n := strings.Count(string(second), pamBlockBegin); n != 1 {
		t.Errorf("counted %d blocks, want 1:\n%s", n, second)
	}
}

// A revoke takes out the branch and nothing else. The rest of the file is the
// distribution's, and an uninstall that trimmed a line of it would be one that
// changed how every account on the host authenticates.
func TestRemovingTheBlockLeavesTheStackAsItWas(t *testing.T) {
	dir := sudoStacks(t)
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	if _, err := removeSudoPamBlock(run.fs); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sudo", "sudo-i"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != stockSudoStack {
			t.Errorf("%s is not what it was before the block went in:\n%s", name, body)
		}
	}
	// And a second removal is not an error on a host that has none.
	if changed, err := removeSudoPamBlock(run.fs); err != nil || changed {
		t.Errorf("removing an absent block reported changed=%v err=%v", changed, err)
	}
}

// One marker without the other is refused rather than guessed at. Where the
// block starts or stops cannot be read off such a file, and a wrong guess
// rewrites the stack that decides every account's sudo.
func TestAHalfMarkedStackIsRefused(t *testing.T) {
	dir := sudoStacks(t)
	path := filepath.Join(dir, "sudo")
	if err := os.WriteFile(path, []byte(pamBlockBegin+"\n"+stockSudoStack), 0o644); err != nil {
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
	if !strings.Contains(string(body), stockSudoStack) {
		t.Errorf("the stack was rewritten by a run that refused:\n%s", body)
	}
}

// A marker quoted inside somebody's comment is not a boundary. Matching it as a
// substring would let a line about faramir in an operator's own note decide
// where the block ends.
func TestAQuotedMarkerIsNotABoundary(t *testing.T) {
	body := []byte("# see '" + pamBlockBegin + "' below\n" + stockSudoStack)
	if _, _, found, err := placePamBlock(body); found || err != nil {
		t.Errorf("a quoted marker was read as a block: found=%v err=%v", found, err)
	}
}

// sudoRsArrangement is a granting host whose sudo is sudo-rs: faramir's service
// reads the environment file with pam_env, and the branch that selects it is in
// both shared stacks.
func sudoRsArrangement(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := sudoStacks(t)
	pinSudo(t, true)

	// The block is the stack on a sudo-rs host, so the layout it renders from and
	// the config doctor reads have to name the same helper and the same
	// environment file. Both follow LibexecDir, which points at this directory.
	run := &runner{layout: testLayout()}
	run.layout.LibexecDir = dir
	run.layout.SudoRs = true
	cfg := &config.Config{}
	cfg.Escalation.ExecUser = run.layout.ExecUser
	cfg.Escalation.PamService = pamServiceName
	cfg.Escalation.Helper = run.layout.PamHelper()
	if err := os.WriteFile(run.layout.SudoEnvFile(),
		[]byte("FARAMIR_OPERATOR=op\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Named on the block's requisite line, so the arrangement is not whole
	// without it.
	if err := os.WriteFile(cfg.Escalation.Helper, []byte("#!/bin/sh\nexit 0\n"),
		0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	return cfg, dir
}

// The whole sudo-rs arrangement passes, and the branch going missing fails.
// /etc/pam.d/sudo is a dpkg conffile: an upgrade that installs the maintainer's
// version drops the block without saying so, and every escalation fails after
// it with nothing naming the cause.
func TestTheSudoRsArrangementFailsWhenTheBranchIsGone(t *testing.T) {
	cfg, dir := sudoRsArrangement(t)
	opts := DoctorOptions{ExecUser: "ex", AgentUser: "op"}

	var whole DoctorReport
	diagnoseSudoArrangement(&whole, opts, cfg)
	if got := only(t, whole); got.Status != StatusOK {
		t.Fatalf("status %q, want %q with the whole arrangement in place: %s",
			got.Status, StatusOK, got.Detail)
	}

	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(stockSudoStack), 0o644); err != nil {
		t.Fatal(err)
	}
	var without DoctorReport
	diagnoseSudoArrangement(&without, opts, cfg)
	finding := only(t, without)
	if finding.Status != StatusFailed {
		t.Errorf("status %q, want %q with the branch gone: %s",
			finding.Status, StatusFailed, finding.Detail)
	}
	if !strings.Contains(finding.Detail, filepath.Join(dir, "sudo")) {
		t.Errorf("the failure does not name the stack it is about: %s", finding.Detail)
	}
}

// A host whose `sudo` alternatives group was switched after an install has an
// arrangement its sudo cannot use: the grant names settings the new binary has
// no word for, and what selects faramir's service is not what that binary
// reads. Both directions, because either flip leaves a host that looks
// installed and escalates nothing.
func TestSwitchingTheSudoAlternativeIsReported(t *testing.T) {
	t.Run("rendered for the original, host now sudo-rs", func(t *testing.T) {
		cfg, _ := sudoArrangement(t)
		pinSudo(t, true)
		var report DoctorReport
		diagnoseSudoArrangement(&report, DoctorOptions{ExecUser: "ex", AgentUser: "op"}, cfg)
		finding := only(t, report)
		if finding.Status != StatusFailed {
			t.Fatalf("status %q, want %q: %s", finding.Status, StatusFailed, finding.Detail)
		}
		if !strings.Contains(finding.Detail, "sudo-rs") {
			t.Errorf("the failure does not name what the host now runs: %s", finding.Detail)
		}
	})
	t.Run("rendered for sudo-rs, host now the original", func(t *testing.T) {
		cfg, _ := sudoRsArrangement(t)
		pinSudo(t, false)
		var report DoctorReport
		diagnoseSudoArrangement(&report, DoctorOptions{ExecUser: "ex", AgentUser: "op"}, cfg)
		finding := only(t, report)
		if finding.Status != StatusFailed {
			t.Fatalf("status %q, want %q: %s", finding.Status, StatusFailed, finding.Detail)
		}
	})
}

// An install that does not grant sudo takes the branch out, whatever the host's
// sudo is now: a re-run without --allow-sudo removes the service the branch
// names, and a branch left pointing at a file that is gone sends the executor to
// /etc/pam.d/other.
func TestRevokingTakesTheBranchOut(t *testing.T) {
	dir := sudoStacks(t)
	pinSudo(t, false)
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
	if strings.Contains(string(body), pamBlockBegin) {
		t.Errorf("the branch outlived the grant:\n%s", body)
	}
}

// A splice that changed anything outside the block is undone rather than left.
// This is a file the distribution owns and every account's sudo reads, so a
// write that came out wrong is a host nobody can sudo on, and an install that
// noticed and carried on would be one that broke a machine quietly.
func TestASpliceThatDamagesTheStackIsPutBack(t *testing.T) {
	dir := sudoStacks(t)
	path := filepath.Join(dir, "sudo")
	// A block whose end marker is missing: what lands parses as half-marked, which
	// is the shape spliceProblem refuses.
	if problem := spliceProblem(path, []byte(stockSudoStack), []byte(pamBlockBegin+"\n")); problem == "" {
		t.Error("a block with no end marker was accepted")
	}
	// And the claim itself, against what is actually on disk: everything outside
	// the block has to come back unchanged.
	before := []byte(stockSudoStack)
	if err := os.WriteFile(path, []byte("something else entirely\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if problem := spliceProblem(path, before, nil); problem == "" {
		t.Error("a stack rewritten out from under the splice was accepted")
	}
}

// The block is cut out of both sides before they are compared, or a run that
// replaced an older block would read as one that ate the file.
func TestTheComparisonIgnoresTheBlockItself(t *testing.T) {
	withBlock := []byte(pamBlockBegin + "\nauth optional pam_permit.so\n" + pamBlockEnd + "\n" + stockSudoStack)
	if got := string(withoutPamBlock(withBlock)); got != stockSudoStack {
		t.Errorf("cutting the block out left %q, want the stock stack", got)
	}
	if got := string(withoutPamBlock([]byte(stockSudoStack))); got != stockSudoStack {
		t.Errorf("a stack with no block was changed: %q", got)
	}
}

// A second factor somebody put on this host's sudo is named rather than stepped
// over in silence: the branch goes above it, so the executor reaches root
// without meeting it. An `include` of the distribution's shared stack is what a
// stock file says and draws nothing.
func TestAThirdPartyAuthModuleIsNamed(t *testing.T) {
	for body, want := range map[string]string{
		stockSudoStack: "",
		"auth include system-auth\n@include common-account\n":                 "",
		"auth substack password-auth\n":                                       "",
		"# auth required pam_duo.so\n@include common-auth\n":                  "",
		"auth required pam_duo.so\n@include common-auth\n":                    "auth required pam_duo.so",
		stockSudoStack + "auth required pam_google_authenticator.so nullok\n": "auth required pam_google_authenticator.so nullok",
	} {
		if got := foreignAuthModule([]byte(body)); got != want {
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
	block, err := render("etc/pam.d-sudo.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	var branch string
	after := 0
	for line := range strings.Lines(uncommented(string(block))) {
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
	lines := strings.Split(strings.TrimSpace(uncommented(string(block))), "\n")
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
	block, err := render("etc/pam.d-sudo.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if problem := pamStackProblem(string(block), layout.PamHelper()); problem != "" {
		t.Errorf("the rendered block is not a stack that gates: %s", problem)
	}
}

// And no service file is written where nothing can be sent to it: sudo-rs
// reaches the service named `sudo` and nothing a caller may name, so one beside
// the block would be a stack nothing reads.
func TestNoServiceFileIsWrittenUnderSudoRs(t *testing.T) {
	dir := sudoStacks(t)
	pinSudo(t, true)
	run := &runner{layout: testLayout()}
	run.layout.SudoRs = true
	run.layout.LibexecDir = dir
	// One left by an install made when this host's sudo was the original.
	if err := os.WriteFile(pamServiceFile, []byte("auth required pam_permit.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	if _, err := run.syncPamService(); err != nil {
		t.Fatal(err)
	}
	if exists(pamServiceFile) {
		t.Errorf("%s is still there on a sudo-rs host, where nothing reads it",
			pamServiceFile)
	}
}

// A block that ended up below the line that authenticates is moved back to the
// top rather than rewritten where it lies. Left there it is a branch nobody
// reaches: the executor meets the password check first and every escalation
// fails, on a host doctor would otherwise call well.
func TestABlockBelowTheAuthLineIsHoistedBack(t *testing.T) {
	dir := sudoStacks(t)
	path := filepath.Join(dir, "sudo")
	run := &runner{layout: testLayout()}
	block, err := render("etc/pam.d-sudo.tmpl", run.layout)
	if err != nil {
		t.Fatal(err)
	}
	// The shape a conffile merge or a hand edit leaves.
	if err := os.WriteFile(path, append([]byte(stockSudoStack), block...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), pamBlockBegin) {
		t.Errorf("the block was left below what authenticates:\n%s", body)
	}
	if n := strings.Count(string(body), pamBlockBegin); n != 1 {
		t.Errorf("counted %d blocks, want 1", n)
	}
	// And doctor agrees, which it did not before: the stock stack authenticates
	// with `@include common-auth` and has no line beginning `auth` at all.
	pinSudo(t, true)
	if problem := sudoPamBranchProblem(run.layout.ExecUser, run.layout.PamHelper()); problem != "" {
		t.Errorf("the hoisted block still reads as misplaced: %s", problem)
	}
	// The same file with the block put back underneath is what must fail.
	if err := os.WriteFile(path, append([]byte(stockSudoStack), block...), 0o644); err != nil {
		t.Fatal(err)
	}
	problem := sudoPamBranchProblem(run.layout.ExecUser, run.layout.PamHelper())
	if problem == "" {
		t.Error("a block sitting below `@include common-auth` was reported as fine")
	}
}

// The jump is checked against what is on the host, not only against what was
// rendered: a block edited by hand to add a module is one whose branch now lands
// inside it, and that authenticates every other account for free.
func TestAJumpThatNoLongerClearsTheBlockIsReported(t *testing.T) {
	dir := sudoStacks(t)
	pinSudo(t, true)
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
	edited := strings.Replace(string(body), pamBlockEnd,
		"auth optional pam_permit.so\n"+pamBlockEnd, 1)
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	problem := sudoPamBranchProblem(run.layout.ExecUser, run.layout.PamHelper())
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
	dir := sudoStacks(t)

	if _, err := escalation.StackFile(dir, pamServiceName); err == nil {
		t.Error("a host with neither arrangement reported a stack")
	}
	// The sudo-rs arrangement: a block, and no service file.
	run := &runner{layout: testLayout()}
	if _, err := run.writeSudoPamBlock(); err != nil {
		t.Fatal(err)
	}
	stack, err := escalation.StackFile(dir, pamServiceName)
	if err != nil {
		t.Fatalf("the block was not recognised as the stack: %v", err)
	}
	if stack != filepath.Join(dir, "sudo") {
		t.Errorf("found %q, want the shared stack", stack)
	}
	// And the classic one: a service file, which wins.
	if err := os.WriteFile(filepath.Join(dir, pamServiceName),
		[]byte("auth requisite pam_exec.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if stack, err = escalation.StackFile(dir, pamServiceName); err != nil ||
		stack != filepath.Join(dir, pamServiceName) {
		t.Errorf("found %q (%v), want the service file", stack, err)
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

// A shared stack that is a symlink to the other one is how some distributions
// ship the login case. The block lands on the target through the real file, so
// the link is already covered and refusing the install over it would fail a host
// that works.
func TestASharedStackLinkedToTheOtherIsAlreadyCovered(t *testing.T) {
	dir := sudoStacks(t)
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
	if n := strings.Count(string(body), pamBlockBegin); n != 1 {
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
	if err := os.WriteFile(outside, []byte(stockSudoStack), 0o644); err != nil {
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
	dir := sudoStacks(t)
	path := filepath.Join(dir, "sudo")
	run := &runner{layout: testLayout()}
	block, err := render("etc/pam.d-sudo.tmpl", run.layout)
	if err != nil {
		t.Fatal(err)
	}
	doubled := append(append(append([]byte{}, block...), block...), []byte(stockSudoStack)...)
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
	if n := strings.Count(string(body), pamBlockBegin); n != 1 {
		t.Errorf("a re-run left %d blocks, want 1:\n%s", n, body)
	}
	// And a revoke takes the file back to what the distribution put there.
	if err := os.WriteFile(path, doubled, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := removeSudoPamBlock(run.fs); err != nil {
		t.Fatal(err)
	}
	if body, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	if string(body) != stockSudoStack {
		t.Errorf("a revoke left a block behind:\n%s", body)
	}
}
