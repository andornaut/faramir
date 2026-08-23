package install

// The block faramir writes into the PAM stacks every account's sudo reads, and
// the only thing this install puts in a file it does not own.
//
// It exists because sudo-rs has no pam_service: the service name is `sudo` for a
// command and `sudo-i` for a login shell, both compiled in, so a host running it
// has no stack of faramir's own for sudo to be pointed at. The block is a branch
// rather than a policy -- it tests the account and sends the executor alone to
// faramir's service, leaving what the file already said to answer for everybody
// else. A host whose sudo is the original gets none of this: pam_service
// selects the service there and nothing shared is touched.
//
// Delimited by markers so a later run can replace exactly what an earlier one
// wrote, and a revoke can take it out again. The rest of the file is the
// distribution's: it is a dpkg conffile, and an upgrade that replaces it drops
// the block, which is what `faramir doctor` looks for.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andornaut/faramir/internal/escalation"
)

// The markers. Whole lines, matched as such: a comment somewhere in the file
// mentioning faramir is not a block boundary.
//
// Taken from internal/escalation rather than spelled again here: the broker
// recognises the same block when it answers whether this host can escalate at
// all, and two spellings of a marker is a block one of them cannot find.
const (
	pamBlockBegin = escalation.BlockBegin
	pamBlockEnd   = escalation.BlockEnd
)

// errHalfMarkedPam is a stack carrying one marker without the other, or an end
// before its begin. Where the block starts or stops cannot be read off the file,
// and a wrong guess rewrites the stack that decides every account's sudo.
var errHalfMarkedPam = errors.New("the faramir block's markers are incomplete")

// placePamBlock finds the span an existing block occupies, including both
// marker lines and the newline after the end. found=false means there is none
// and a block would go at the top.
//
// The top, not the bottom: the branch has to be reached before anything that
// could authenticate, and a stack whose first module is a password check has
// already refused the executor by the time a block below it runs.
func placePamBlock(current []byte) (start, end int, found bool, err error) {
	begin := lineIndex(current, pamBlockBegin)
	stop := lineIndex(current, pamBlockEnd)
	switch {
	case begin < 0 && stop < 0:
		return 0, 0, false, nil
	case begin < 0 || stop < begin:
		return 0, 0, false, errHalfMarkedPam
	}
	end = stop + len(pamBlockEnd)
	if end < len(current) && current[end] == '\n' {
		end++
	}
	return begin, end, true, nil
}

// lineIndex is bytes.Index for a marker that must be a line of its own, so a
// marker quoted inside a comment somebody wrote is not mistaken for one.
func lineIndex(body []byte, marker string) int {
	for at := 0; at < len(body); {
		next := bytes.Index(body[at:], []byte(marker))
		if next < 0 {
			return -1
		}
		next += at
		afterStart := next == 0 || body[next-1] == '\n'
		tail := next + len(marker)
		atEnd := tail == len(body) || body[tail] == '\n'
		if afterStart && atEnd {
			return next
		}
		at = next + len(marker)
	}
	return -1
}

// spliceSudoPamBlock puts block at the top of one shared stack, replacing what a
// previous run left. An empty block removes what is there and writes nothing
// otherwise.
//
// The file's own mode and owner are kept rather than asserted: this is the
// distribution's file, and faramir owning a delimited block in it is not a claim
// on the rest.
func spliceSudoPamBlock(fs fsys, path string, block []byte) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// No such stack on this host. `sudo-i` is absent on distributions that do
		// not split the login case out, and its absence is not a broken install:
		// what is missing is a launch type, not the escalation.
		return false, nil
	case err != nil:
		return false, err
	case info.Mode()&os.ModeSymlink != 0:
		// One shared stack pointing at another is how some distributions ship the
		// login case, and the block has already landed on the target or is about to.
		// Writing through the link would splice the same file twice.
		if sharedStackTarget(path) {
			return false, nil
		}
		return false, fmt.Errorf("%s is a symlink, and a block written through it "+
			"would land on whatever it points at: replace it with a real file, or "+
			"install without --allow-sudo", path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		if fs.dryRun {
			// A dry run runs unprivileged and cannot read every mode. Reported as a
			// change, so the rest of the plan is still produced.
			return true, nil
		}
		return false, err
	}
	// The span is not needed: the write below is built from the stack with every
	// block cut out. What this asks is whether there was one, and whether the
	// markers can be read at all.
	_, _, found, err := placePamBlock(current)
	if err != nil {
		return false, fmt.Errorf("%s: %w: nothing was written. Delete the stray marker and re-run, or edit by hand: "+
			"the lines between %q and %q are faramir's", path, err, pamBlockBegin, pamBlockEnd)
	}
	// Always at the top, a replacement included. Leaving a block where it was
	// found keeps whatever put it below an authenticating line there through every
	// re-run, which is a host whose executor meets the password check first and
	// whose every escalation fails.
	rest := withoutPamBlock(current)
	var out []byte
	switch {
	case len(block) == 0 && !found:
		return false, nil
	case len(block) == 0:
		out = rest
	default:
		out = append(append([]byte{}, block...), rest...)
	}
	changed, err := fs.writeFile(path, out, info.Mode().Perm(), keep, keep)
	if err != nil || !changed || fs.dryRun {
		return changed, err
	}
	// What landed, read back off the disk. This is a file the distribution owns
	// and every account's sudo reads, so the window between writing it and finding
	// out it is wrong is a window in which nobody on the host can sudo. Closed by
	// looking, and by putting the file back when the answer is no.
	if problem := spliceProblem(path, current, block); problem != "" {
		if _, undo := fs.writeFile(path, current, info.Mode().Perm(), keep, keep); undo != nil {
			return false, fmt.Errorf("%s: %s, and putting the file back failed too "+
				"(%w). Restore it by hand before anything else: until it says what it "+
				"said, this host's sudo is not what its operators expect", path, problem, undo)
		}
		return false, fmt.Errorf("%s: %s. The file was put back as it was, and "+
			"nothing was granted", path, problem)
	}
	return changed, nil
}

// spliceProblem says what is wrong with what landed, or "".
//
// Two claims, both read off the file rather than off what was meant to be
// written: the block is byte for byte what this run rendered, and everything
// outside it is byte for byte what was there before. The second is the one worth
// the read -- a splice that ate a line of the distribution's stack is a host
// that authenticates differently now, and nothing else here would notice.
func spliceProblem(path string, before, block []byte) string {
	landed, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("it cannot be read back (%v), so what landed is unknown", err)
	}
	start, end, found, err := placePamBlock(landed)
	switch {
	case err != nil:
		return "the block that landed carries one marker without the other"
	case len(block) == 0 && found:
		return "the block is still there after a removal"
	case len(block) > 0 && !found:
		return "no faramir block is there after writing one"
	case len(block) > 0 && !bytes.Equal(landed[start:end], block):
		return "the block that landed is not the one this run rendered"
	}
	if !bytes.Equal(withoutPamBlock(landed), withoutPamBlock(before)) {
		return "the rest of the file is no longer what it was, so the splice " +
			"changed how every account on this host authenticates"
	}
	return ""
}

// withoutPamBlock is a stack with every faramir block cut out, which is the part
// that must survive a write untouched. A half-marked file is returned whole:
// spliceProblem names that case before this is reached.
//
// Every one, not the first: a file that somehow carries two is a file with two
// branches, and taking out only the one this run can see would leave the other
// there through every re-run and every revoke, with nothing able to remove it.
func withoutPamBlock(body []byte) []byte {
	for {
		start, end, found, err := placePamBlock(body)
		if err != nil || !found {
			return body
		}
		body = append(append([]byte{}, body[:start]...), body[end:]...)
	}
}

// sharedStackTarget reports whether a link points at another of the shared
// stacks. Both sides are resolved before they are compared: EvalSymlinks returns
// a canonical path, and a directory that is itself reached through a link would
// otherwise never match a name built from pamDir, turning a stack that is
// already covered into a refused install.
func sharedStackTarget(path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for _, candidate := range sudoPamFiles() {
		if candidate == path {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil && resolved == target {
			return true
		}
	}
	return false
}

// writeSudoPamBlock puts the branch into every shared stack, which is what
// selects faramir's PAM service on a host whose sudo is sudo-rs.
//
// After the service file it names: a branch pointing at a service that is not
// there sends the executor to /etc/pam.d/other, which asks for a password
// nothing supplies.
func (r *runner) writeSudoPamBlock() (bool, error) {
	block, err := render("etc/pam.d-sudo.tmpl", r.layout)
	if err != nil {
		return false, err
	}
	changed, landed := false, 0
	for _, path := range r.layout.SudoPamFiles() {
		if !exists(path) {
			continue
		}
		landed++
		r.warnForeignAuthModule(path)
		wrote, err := spliceSudoPamBlock(r.fs, path, block)
		if err != nil {
			return false, err
		}
		changed = changed || wrote
	}
	// Nowhere to put it. The grant is written either way, so this is the
	// difference between a host that escalates and one whose every sudo falls to
	// /etc/pam.d/other -- said here rather than left for the broker's own check,
	// which reports it in a sentence about the broker.
	if landed == 0 {
		r.warnf("this host's sudo is sudo-rs, which reaches the service named `sudo` and nothing a "+
			"caller may name, and neither %s exists to carry the stack that asks the broker: "+
			"every escalation falls to %s/other. Install sudo, then re-run this install",
			strings.Join(r.layout.SudoPamFiles(), " nor "), pamDir)
	}
	return changed, nil
}

// warnForeignAuthModule reports a stack that already authenticates with a module
// of somebody else's, which on these two files is usually a second factor.
//
// The block goes above it, and that is the right way round: for every other
// account the branch falls through and the module still runs, and for the
// executor the broker is the second factor already -- a human is being asked. It
// is still not faramir's call to make quietly. An operator who put a factor on
// this host's sudo should hear that one account now reaches root without it,
// and that two things are editing a file neither owns.
func (r *runner) warnForeignAuthModule(path string) {
	current, err := os.ReadFile(path)
	if err != nil {
		return
	}
	module := foreignAuthModule(withoutPamBlock(current))
	if module == "" {
		return
	}
	r.warnf("%s authenticates with a module of its own (%q) and faramir's branch goes above it, "+
		"so %s reaches root without meeting it. Every other account still does. Review this "+
		"if that module is a second factor", path, module, r.layout.ExecUser)
}

// foreignAuthModule is the first auth line naming a module rather than pulling
// in the distribution's shared stack, or "".
//
// An `auth include system-auth` or `@include common-auth` is what a stock file
// says and is not worth a word; a `pam_duo.so` or a `pam_google_authenticator.so`
// is something somebody added to this host on purpose.
func foreignAuthModule(body []byte) string {
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "auth"))
		if strings.HasPrefix(rest, "include") || strings.HasPrefix(rest, "substack") {
			continue
		}
		return line
	}
	return ""
}

// sudoPamBranchProblem says what is wrong with the branch in the shared stacks,
// or "". It is the whole of what selects faramir's service on a sudo-rs host, so
// a stack that lost it is a host where every escalation fails, and one that kept
// a branch it cannot reach is worse: the executor meets the password check
// below and the question is never put.
//
// /etc/pam.d/sudo is a dpkg conffile. An upgrade that installs the maintainer's
// version drops the block without saying so, which is the failure this exists to
// name.
func sudoPamBranchProblem(execUser, helper string) string {
	// How many shared stacks were there to check. None at all is not a pass: on a
	// sudo-rs host the branch is the whole of what selects faramir's service, so a
	// host with nowhere to put it is one where every escalation reaches
	// /etc/pam.d/other instead.
	checked := 0
	for _, path := range sudoPamFiles() {
		current, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			// A launch type this distribution does not split out. Nothing selects a
			// service that is never asked for.
			continue
		}
		checked++
		if err != nil {
			return fmt.Sprintf("%s cannot be read (%v), so what decides an escalation "+
				"there went unchecked. Re-run as root", path, err)
		}
		start, _, found, err := placePamBlock(current)
		switch {
		case err != nil:
			return fmt.Sprintf("%s carries one faramir marker without the other, so "+
				"what the block is cannot be read off it. Fix the markers by hand and "+
				"re-run `faramir init --allow-sudo`", path)
		case !found:
			return fmt.Sprintf("%s carries no faramir block, so this host's sudo-rs sends %s to the stock stack, "+
				"where its locked password refuses: every escalation fails. A package upgrade "+
				"replaced that file, or the install was made when the `sudo` alternatives group "+
				"pointed elsewhere. Re-run `faramir init --allow-sudo`", path, execUser)
		}
		block := string(current[start:])
		if at := strings.Index(block, pamBlockEnd); at >= 0 {
			block = block[:at]
		}
		switch {
		case !strings.Contains(block, "pam_succeed_if.so"):
			return fmt.Sprintf("%s's faramir block does not test which account is authenticating, so it applies "+
				"to every account rather than to %s alone. Re-run `faramir init --allow-sudo`",
				path, execUser)
		case execUser == "":
			return fmt.Sprintf("which account runs the executor is not known here, so "+
				"whether %s's faramir block tests for it went unchecked. Pass "+
				"--exec-user", path)
		case !strings.Contains(block, "user = "+execUser):
			return fmt.Sprintf("%s's faramir block tests for an account that is not "+
				"%s, so the executor falls through to the stock stack and every "+
				"escalation fails. Re-run `faramir init --allow-sudo`", path, execUser)
		case helper != "" && !strings.Contains(block, helper):
			return fmt.Sprintf("%s's faramir block does not exec %s, so something "+
				"other than faramir decides these escalations. Re-run "+
				"`faramir init --allow-sudo`", path, helper)
		}
		// The jump has to clear every faramir module below it. One short and it
		// lands on this block's own pam_permit, which authenticates every account
		// the branch was meant to let past.
		if problem := branchJumpProblem(path, block); problem != "" {
			return problem
		}
		if before := firstAuthLine(current[:start]); before != "" {
			return fmt.Sprintf("%s has an auth line ahead of the faramir block (%q), "+
				"so %s meets it before the branch is reached. Re-run "+
				"`faramir init --allow-sudo`", path, before, execUser)
		}
	}
	if checked == 0 {
		return fmt.Sprintf("this host's sudo is sudo-rs, which reaches the service named `sudo` alone, and "+
			"neither %s exists to carry the stack that asks the broker: every escalation falls "+
			"to %s/other. Install sudo, then re-run `faramir init --allow-sudo`",
			strings.Join(sudoPamFiles(), " nor "), pamDir)
	}
	return ""
}

// branchJumpProblem checks the arithmetic that decides who meets what: the
// branch's `default=N` must skip every auth line after it inside the block.
//
// One short and an account that is not the executor lands on the block's own
// `sufficient pam_permit`, which authenticates it with no password. This is the
// worst thing this file can get wrong, so it is checked on a host rather than
// only against what was rendered.
func branchJumpProblem(path, block string) string {
	jump, after := -1, 0
	for line := range strings.Lines(block) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		if jump < 0 {
			at := strings.Index(line, "default=")
			if at < 0 {
				return fmt.Sprintf("%s's faramir block does not branch on the account "+
					"at all, so it applies to everybody. Re-run `faramir init --allow-sudo`",
					path)
			}
			rest := line[at+len("default="):]
			end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
			if end >= 0 {
				rest = rest[:end]
			}
			n, err := strconv.Atoi(rest)
			if err != nil {
				return fmt.Sprintf("%s's faramir block does not jump a number of "+
					"modules (%q). Re-run `faramir init --allow-sudo`", path, line)
			}
			jump = n
			continue
		}
		after++
	}
	if jump >= 0 && jump != after {
		return fmt.Sprintf("%s's faramir block skips %d module(s) and has %d after the branch, so an account "+
			"that is not the executor lands inside it and is authenticated without a password. "+
			"Re-run `faramir init --allow-sudo`",
			path, jump, after)
	}
	return ""
}

// firstAuthLine is the first thing in a stack that can authenticate, or "".
// What is ahead of the block decides whether the branch is reached at all.
//
// An `@include` counts. The stock Debian and Ubuntu /etc/pam.d/sudo has no line
// beginning `auth` at all -- it authenticates with `@include common-auth` -- so
// a check that only looked for the one would report a block sitting below the
// other as correctly placed, on the file this is most likely to be reading.
func firstAuthLine(body []byte) string {
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "auth"):
			return line
		case strings.HasPrefix(line, "@include"):
			// Pulls in every type, auth among them.
			return line
		}
	}
	return ""
}

// sudoPamBlock is the block's own lines, markers included, read off a shared
// stack. On a sudo-rs host these are faramir's whole PAM stack, so they are what
// the checks that read a stack are put to.
func sudoPamBlock(path string) ([]byte, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("it cannot be read (%w), so what decides an "+
			"escalation here went unchecked", err)
	}
	start, end, found, err := placePamBlock(current)
	switch {
	case err != nil:
		return nil, errHalfMarkedPam
	case !found:
		return nil, errors.New("it carries no faramir block, so nothing sends the " +
			"executor to a stack that asks the broker")
	}
	return current[start:end], nil
}

// firstExistingStack is the shared stack a diagnosis should read, which is the
// first one this host actually has. Falls back to the first name so a message
// about a host with neither still names a path.
func firstExistingStack() string {
	for _, path := range sudoPamFiles() {
		if exists(path) {
			return path
		}
	}
	return sudoPamFiles()[0]
}

// sudoPamBlockPresent reports whether any shared stack still carries one. A
// half-marked file answers yes: something is there, and the removal is what says
// it cannot be read off.
func sudoPamBlockPresent() (bool, error) {
	for _, path := range sudoPamFiles() {
		current, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if lineIndex(current, pamBlockBegin) >= 0 || lineIndex(current, pamBlockEnd) >= 0 {
			return true, nil
		}
	}
	return false, nil
}

// removeSudoPamBlock takes it back out. Run on every revoke and every uninstall
// whatever the host's sudo is now: an install that wrote the block and an
// operator who has since switched the alternatives group would otherwise leave a
// branch behind, pointing at a service the same run deleted.
func removeSudoPamBlock(fs fsys) (bool, error) {
	changed := false
	for _, path := range sudoPamFiles() {
		removed, err := spliceSudoPamBlock(fs, path, nil)
		if err != nil {
			return false, err
		}
		changed = changed || removed
	}
	return changed, nil
}
