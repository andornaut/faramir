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
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
		return false, fmt.Errorf("%s is a symlink, and a block written through "+
			"it would land on its target. Replace it with a real file, or install without "+
			"--allow-sudo", path)
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
			return false, fmt.Errorf("%s: %s, and restoring the file failed too "+
				"(%w). Restore it by hand before anything else: until it is back as it was, "+
				"this host's sudo is not what its operators expect", path, problem, undo)
		}
		return false, fmt.Errorf("%s: %s. The file was restored as it was, and "+
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
		return fmt.Sprintf("it cannot be read back (%v), so what was written is "+
			"unknown", err)
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
