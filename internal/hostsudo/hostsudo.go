// Package hostsudo is the sudo arrangement on a host: which sudo is installed,
// and the block faramir writes into the PAM stacks that sudo reads.
//
// It exists because sudo-rs has no pam_service. The service name is compiled in
// there, so a host running it has no stack of faramir's own for sudo to be
// pointed at, and the executor's authentication has to be branched out of the
// shared stack instead. Which arrangement a host gets follows the `sudo`
// alternative, which an operator changes without telling faramir, so it is
// probed rather than configured.
//
// One reader for both tiers. Provisioning splices the block in and takes it
// back out, and a diagnosis reads a stack to say whether what is there still
// holds; a second reader of the same file would be free to disagree with the
// first about where the block starts.
package hostsudo

// The block is a branch rather than a policy: it tests the account and sends the
// executor alone to faramir's service, leaving what the file already said to
// answer for everybody else. A host whose sudo is the original gets none of it,
// pam_service selecting the service there and nothing shared being touched.
//
// Delimited by markers so a later run can replace exactly what an earlier one
// wrote, and a revoke can take it out again. The rest of the file is the
// distribution's: it is a dpkg conffile, and an upgrade that replaces it drops
// the block, which is what `faramir doctor` looks for.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// The markers. Whole lines, matched as such: a comment somewhere in the file
// mentioning faramir is not a block boundary.
//
// Taken from internal/escalation rather than spelled again here: the broker
// recognises the same block when it answers whether this host can escalate at
// all, and two spellings of a marker is a block one of them cannot find.
const (
	PamBlockBegin = escalation.BlockBegin
	PamBlockEnd   = escalation.BlockEnd
)

// errHalfMarkedPam is a stack carrying one marker without the other, or an end
// before its begin. Where the block starts or stops cannot be read off the file,
// and a wrong guess rewrites the stack that decides every account's sudo.
var errHalfMarkedPam = errors.New("the faramir block's markers are incomplete")

// placeBlock finds the span an existing block occupies, including both
// marker lines and the newline after the end. found=false means there is none
// and a block would go at the top.
//
// The top, not the bottom: the branch has to be reached before anything that
// could authenticate, and a stack whose first module is a password check has
// already refused the executor by the time a block below it runs.
func placeBlock(current []byte) (start, end int, found bool, err error) {
	begin := lineIndex(current, PamBlockBegin)
	stop := lineIndex(current, PamBlockEnd)
	switch {
	case begin < 0 && stop < 0:
		return 0, 0, false, nil
	case begin < 0 || stop < begin:
		return 0, 0, false, errHalfMarkedPam
	}
	end = stop + len(PamBlockEnd)
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

// SpliceBlock puts block at the top of one shared stack, replacing what a
// previous run left. An empty block removes what is there and writes nothing
// otherwise.
//
// The file's own mode and owner are kept rather than asserted: this is the
// distribution's file, and faramir owning a delimited block in it is not a claim
// on the rest.
func SpliceBlock(fs hostfs.FS, path string, block []byte) (bool, error) {
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
		if fs.DryRun {
			// A dry run runs unprivileged and cannot read every mode. Reported as a
			// change, so the rest of the plan is still produced.
			return true, nil
		}
		return false, err
	}
	// The span is not needed: the write below is built from the stack with every
	// block cut out. What this asks is whether there was one, and whether the
	// markers can be read at all.
	_, _, found, err := placeBlock(current)
	if err != nil {
		return false, fmt.Errorf("%s: %w: nothing was written. Delete the stray marker and re-run, or edit by hand: "+
			"the lines between %q and %q are faramir's", path, err, PamBlockBegin, PamBlockEnd)
	}
	// Always at the top, a replacement included. Leaving a block where it was
	// found keeps whatever put it below an authenticating line there through every
	// re-run, which is a host whose executor meets the password check first and
	// whose every escalation fails.
	rest := WithoutBlock(current)
	var out []byte
	switch {
	case len(block) == 0 && !found:
		return false, nil
	case len(block) == 0:
		out = rest
	default:
		out = append(append([]byte{}, block...), rest...)
	}
	changed, err := fs.WriteFile(path, out, info.Mode().Perm(), hostfs.Keep, hostfs.Keep)
	if err != nil || !changed || fs.DryRun {
		return changed, err
	}
	// What landed, read back off the disk. This is a file the distribution owns
	// and every account's sudo reads, so the window between writing it and finding
	// out it is wrong is a window in which nobody on the host can sudo. Closed by
	// looking, and by putting the file back when the answer is no.
	if problem := spliceProblem(path, current, block); problem != "" {
		if _, undo := fs.WriteFile(path, current, info.Mode().Perm(), hostfs.Keep, hostfs.Keep); undo != nil {
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
	start, end, found, err := placeBlock(landed)
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
	if !bytes.Equal(WithoutBlock(landed), WithoutBlock(before)) {
		return "the rest of the file is no longer what it was, so the splice " +
			"changed how every account on this host authenticates"
	}
	return ""
}

// WithoutBlock is a stack with every faramir block cut out, which is the part
// that must survive a write untouched. A half-marked file is returned whole:
// spliceProblem names that case before this is reached.
//
// Every one, not the first: a file that somehow carries two is a file with two
// branches, and taking out only the one this run can see would leave the other
// there through every re-run and every revoke, with nothing able to remove it.
func WithoutBlock(body []byte) []byte {
	for {
		start, end, found, err := placeBlock(body)
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
	for _, candidate := range hostlayout.SudoPamStacks() {
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

// ForeignAuthModule is the first auth line naming a module rather than pulling
// in the distribution's shared stack, or "".
//
// An `auth include system-auth` or `@include common-auth` is what a stock file
// says and is not worth a word; a `pam_duo.so` or a `pam_google_authenticator.so`
// is something somebody added to this host on purpose.
func ForeignAuthModule(body []byte) string {
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

// BranchProblem says what is wrong with the branch in the shared stacks,
// or "". It is the whole of what selects faramir's service on a sudo-rs host, so
// a stack that lost it is a host where every escalation fails, and one that kept
// a branch it cannot reach is worse: the executor meets the password check
// below and the question is never put.
//
// /etc/pam.d/sudo is a dpkg conffile. An upgrade that installs the maintainer's
// version drops the block without saying so, which is the failure this exists to
// name.
func BranchProblem(execUser, helper string) string {
	// How many shared stacks were there to check. None at all is not a pass: on a
	// sudo-rs host the branch is the whole of what selects faramir's service, so a
	// host with nowhere to put it is one where every escalation reaches
	// /etc/pam.d/other instead.
	checked := 0
	for _, path := range hostlayout.SudoPamStacks() {
		current, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			// A launch type this distribution does not split out. Nothing selects a
			// service that is never asked for.
			continue
		}
		checked++
		if err != nil {
			return fmt.Sprintf("%s cannot be read (%v), so what decides an escalation "+
				"there went unchecked. The operator can re-run this as root", path, err)
		}
		start, _, found, err := placeBlock(current)
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
		if at := strings.Index(block, PamBlockEnd); at >= 0 {
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
		if before := FirstAuthLine(current[:start]); before != "" {
			return fmt.Sprintf("%s has an auth line ahead of the faramir block (%q), "+
				"so %s meets it before the branch is reached. Re-run "+
				"`faramir init --allow-sudo`", path, before, execUser)
		}
	}
	if checked == 0 {
		return fmt.Sprintf("this host's sudo is sudo-rs, which reaches the service named `sudo` alone, and "+
			"neither %s exists to carry the stack that asks the broker: every escalation falls "+
			"to %s/other. Install sudo, then re-run `faramir init --allow-sudo`",
			strings.Join(hostlayout.SudoPamStacks(), " nor "), hostlayout.PamDir)
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

// FirstAuthLine is the first thing in a stack that can authenticate, or "".
// What is ahead of the block decides whether the branch is reached at all.
//
// An `@include` counts. The stock Debian and Ubuntu /etc/pam.d/sudo has no line
// beginning `auth` at all -- it authenticates with `@include common-auth` -- so
// a check that only looked for the one would report a block sitting below the
// other as correctly placed, on the file this is most likely to be reading.
func FirstAuthLine(body []byte) string {
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

// Block is the block's own lines, markers included, read off a shared
// stack. On a sudo-rs host these are faramir's whole PAM stack, so they are what
// the checks that read a stack are put to.
func Block(path string) ([]byte, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("it cannot be read (%w), so what decides an "+
			"escalation here went unchecked", err)
	}
	start, end, found, err := placeBlock(current)
	switch {
	case err != nil:
		return nil, errHalfMarkedPam
	case !found:
		return nil, errors.New("it carries no faramir block, so nothing sends the " +
			"executor to a stack that asks the broker")
	}
	return current[start:end], nil
}

// FirstExistingStack is the shared stack a diagnosis should read, which is the
// first one this host actually has. Falls back to the first name so a message
// about a host with neither still names a path.
func FirstExistingStack() string {
	for _, path := range hostlayout.SudoPamStacks() {
		if hostfs.Exists(path) {
			return path
		}
	}
	return hostlayout.SudoPamStacks()[0]
}

// BlockPresent reports whether any shared stack still carries one. A
// half-marked file answers yes: something is there, and the removal is what says
// it cannot be read off.
func BlockPresent() (bool, error) {
	for _, path := range hostlayout.SudoPamStacks() {
		current, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if lineIndex(current, PamBlockBegin) >= 0 || lineIndex(current, PamBlockEnd) >= 0 {
			return true, nil
		}
	}
	return false, nil
}

// RemoveBlock takes it back out. Run on every revoke and every uninstall
// whatever the host's sudo is now: an install that wrote the block and an
// operator who has since switched the alternatives group would otherwise leave a
// branch behind, pointing at a service the same run deleted.
func RemoveBlock(fs hostfs.FS) (bool, error) {
	changed := false
	for _, path := range hostlayout.SudoPamStacks() {
		removed, err := SpliceBlock(fs, path, nil)
		if err != nil {
			return false, err
		}
		changed = changed || removed
	}
	return changed, nil
}

// VersionNote names the version floor the grant sits on, or "".
//
// The grant is rendered for whichever sudo this host has, so a rejection is no
// longer a question of which implementation is installed but of how old it is.
// Both grew `noninteractive_auth` after their first releases, and it is the one
// setting here that a sudo old enough will not know: `unknown setting` from
// visudo reads as a typo in a directive faramir wrote deliberately, and every
// other line of the grant is reported as invalid with it.
//
// Read only once the check has failed. A version probe on every install would be
// a command run to say nothing on every host that works.
func VersionNote(visudo string) string {
	out, err := exec.CommandContext(context.Background(), visudo, "-V").CombinedOutput()
	if err != nil {
		return ""
	}
	banner := strings.TrimSpace(firstLine(string(out)))
	floor, older := "sudo 1.9.11", olderThanFloor(banner)
	// bannerIsSudoRs, not a substring: sudo-rs 0.2.2 answers visudo -V with
	// "visudo version 0.2.2" and names no implementation, and that is exactly the
	// release this note is most likely to be printed for.
	if bannerIsRs(banner) {
		floor = "sudo-rs 0.2.9"
	}
	// Only where the version is a cause this rejection could have. Every other
	// rejection is about the file, which visudo has already said its piece about,
	// and a note on all of them sends operators after a sudo upgrade they do not
	// need. Silent where the version could not be read: a guess is worse than
	// nothing.
	if !older {
		return ""
	}
	return "\nThis host reports " + banner + ". The grant needs " + floor +
		"or newer, that being where noninteractive_auth arrived: without it `sudo -n` fails " +
		"before the PAM stack runs, so no question is put. Upgrade sudo, or install without " +
		"--allow-sudo"
}

// olderThanFloor reports whether a version banner names a release without
// noninteractive_auth: sudo before 1.9.11, sudo-rs before 0.2.9. A banner it
// cannot parse answers false, so an unrecognised sudo draws no note.
func olderThanFloor(banner string) bool {
	digits := func(s string) []int {
		var out []int
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r < '0' || r > '9'
		}) {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	fields := strings.Fields(banner)
	version := ""
	for _, field := range fields {
		if strings.ContainsAny(field, "0123456789") && strings.Contains(field, ".") {
			version = field
			break
		}
	}
	parts := digits(version)
	if len(parts) < 3 {
		return false
	}
	floor := []int{1, 9, 11}
	if bannerIsRs(banner) {
		floor = []int{0, 2, 9}
	}
	for i := range floor {
		if parts[i] != floor[i] {
			return parts[i] < floor[i]
		}
	}
	return false
}

// firstLine is what a version banner's first line says, both implementations
// printing more than one.
func firstLine(text string) string {
	head, _, _ := strings.Cut(text, "\n")
	return head
}

// RsProbe answers the question, a variable so a test can answer for a host
// whose sudo is the other one. Nothing else here is stubbed: what it returns is
// the only thing the rest of the package reads.
var RsProbe = probeRs

// probeRs reports whether this host's sudo is sudo-rs.
//
// It asks the binaries rather than the distribution. Both are packaged behind
// one `sudo` alternatives group whose members an operator switches between, so
// which one a host has is a question about what /usr/bin/sudo resolves to today
// and not about its release.
//
// sudo first, not visudo, and that is not arbitrary: sudo-rs 0.2.2 answers
// `visudo -V` with "visudo version 0.2.2", which names no implementation and
// reads exactly like the original's banner. Its `sudo -V` says "sudo-rs 0.2.2".
// Asking the binary the grant is actually for is both more direct and the one
// that has answered on every release seen.
//
// A host with neither on PATH is treated as classic, which is the arrangement
// that has to be wrong out loud: visudo is what refuses a grant the host's sudo
// cannot read, and refuseInvalidSudoers runs before anything is written.
func probeRs() bool {
	for _, program := range []string{"sudo", "visudo"} {
		path, err := exec.LookPath(program)
		if err != nil {
			continue
		}
		out, err := exec.CommandContext(context.Background(), path, "-V").CombinedOutput()
		if err != nil {
			continue
		}
		return bannerIsRs(firstLine(string(out)))
	}
	return false
}

// bannerIsRs reads an implementation off a version banner.
//
// "sudo-rs 0.2.13-0ubuntu1" and "visudo-rs 0.2.14" name themselves. "visudo
// version 0.2.2" does not, and is sudo-rs all the same: the version is the only
// thing separating it from the original's "Sudo version 1.9.17p2", the original
// having been past 1.0 since long before either of these existed. So a leading
// 0 answers where the name does not.
//
// That second test stops meaning anything the day sudo-rs releases a 1.0, and it
// is a fallback rather than the answer: probeSudoRs asks `sudo` first, whose
// banner has named itself on every release seen, 0.2.2 included. What this
// covers is the host where only visudo could be reached.
func bannerIsRs(banner string) bool {
	if strings.Contains(strings.ToLower(banner), "sudo-rs") {
		return true
	}
	for field := range strings.FieldsSeq(banner) {
		if !strings.Contains(field, ".") || !strings.ContainsAny(field, "0123456789") {
			continue
		}
		major, _, _ := strings.Cut(field, ".")
		return major == "0"
	}
	return false
}

// StackProblem names what is wrong with the authentication stack, or "".
// Two things decide whether it gates anything. `requisite` on the helper: with
// `sufficient` a refusal is not fatal, the stack falls through to whatever
// permits below, and every escalation is granted without asking. And
// `seteuid`: without it pam_exec runs the helper with the real uid, which under
// setuid sudo is the executor's own, and the broker answers the escalate op to
// root alone.
func StackProblem(body, helper string) string {
	// Position matters as much as the helper line itself: an auth entry ahead of
	// it authenticates before the broker is asked, and the requisite below then
	// gates nothing. Ahead of the helper only the sudo-rs block's own branch may
	// stand, a pam_succeed_if under a [success=ok ...] spec; the sudo-rs path
	// holds what is outside the block to the same rule with firstAuthLine.
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@include") {
			return "an @include ahead of the helper pulls in an auth stack that " +
				"answers before the broker is asked (" + line + "). Re-run " +
				"`faramir init --allow-sudo`"
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "auth" {
			continue
		}
		control, rest := authLine(fields)
		module := ""
		if len(rest) > 0 {
			module = rest[0]
		}
		if module != "pam_exec.so" {
			if module == "pam_succeed_if.so" && strings.HasPrefix(control, "[success=ok ") {
				continue
			}
			return "an auth line ahead of the helper answers before the broker is " +
				"asked (" + line + "). Re-run `faramir init --allow-sudo`"
		}
		// The helper line, each word matched as the field it is rather than as a
		// substring anything on the line could carry.
		switch {
		case control != "requisite":
			return "the helper is not `requisite`, so a refusal falls through to whatever permits " +
				"below and every escalation is granted without asking. Re-run `faramir init " +
				"--allow-sudo`"
		case !slices.Contains(rest, "seteuid"):
			return "the helper runs without `seteuid`, so pam_exec runs it as the executor rather " +
				"than root, and the broker answers the escalate op to root alone: every " +
				"escalation fails. Re-run `faramir init --allow-sudo`"
		case helper != "" && !slices.Contains(rest, helper):
			return "the helper is not " + helper + ", so something other than faramir " +
				"decides these escalations"
		}
		return ""
	}
	return "no pam_exec auth line, so nothing asks the broker and whatever else " +
		"is in this file decides. Re-run `faramir init --allow-sudo`"
}

// authLine splits one auth entry into its control field, a bracketed spec
// kept whole, and the module with its arguments after it.
func authLine(fields []string) (control string, rest []string) {
	if len(fields) < 2 {
		return "", nil
	}
	i := 2
	if strings.HasPrefix(fields[1], "[") {
		for i < len(fields) && !strings.HasSuffix(fields[i-1], "]") {
			i++
		}
	}
	return strings.Join(fields[1:i], " "), fields[i:]
}

// PermissiveAuth reports whether a stack authenticates without asking: a
// pam_permit with nothing that can refuse ahead of it.
func PermissiveAuth(body string) bool {
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		if strings.Contains(line, "pam_permit.so") {
			return true
		}
		// Anything else in the auth stack (a unix check, a deny, an include) means
		// the fallback is not a free pass.
		return false
	}
	return false
}
