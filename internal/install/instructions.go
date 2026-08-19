package install

// The credentials instructions faramir writes into the prose a coding agent
// reads, at two scopes. `init` writes the account-wide section into each
// agent's home instructions file, the deny rules there holding wherever the
// agent works and otherwise arriving at the model as a bare refusal;
// `init-project` writes the fuller section into the tree's.
//
// Documentation, not enforcement: deleting either block changes nothing about
// what is reachable.

import (
	"bytes"
	"errors"
	"os"
	"strings"
)

// The markers delimiting a section, which is what lets a later run replace what
// an earlier one wrote. These files are prose an operator edits and asks
// agents to rewrite, so a marker can be tidied out; that case is placeWrap,
// which finds the section by its own text and puts the markers back.
const (
	sectionBegin = "<!-- BEGIN faramir: credentials -->"
	sectionEnd   = "<!-- END faramir: credentials -->"
)

// instructionsMode matches what the agent config files are written with, and is
// kept out of a shared tree for the same reason: see sharetree.Options.Keep.
const instructionsMode = 0o640

// The files that are left alone. Returned rather than repaired, so each caller
// can name the command that would write the section afresh.
var (
	// errHalfMarked is a file carrying one marker without the other.
	errHalfMarked = errors.New("the section markers are incomplete")
	// errStaleSection is a file with no markers already carrying a credentials
	// section in words that are not these.
	errStaleSection = errors.New("an undelimited credentials section is already there")
)

// Where a section goes, which is also what decides whether it can be written at
// all.
type sectionPlacement int

const (
	// placeAppend is a file with no block in it, and an empty or missing file.
	placeAppend sectionPlacement = iota
	// placeReplace is a file carrying both markers in order. The span between
	// them is faramir's to rewrite whatever it now says.
	placeReplace
	// placeWrap is a file carrying the section's text and no markers. Wrapped
	// where it stands rather than appended, an append leaving the file with two
	// credentials sections.
	placeWrap
	// placeRefuse is one marker without the other, or an end before its begin:
	// where the block starts or stops cannot be read off the file, and a wrong
	// guess rewrites somebody's prose.
	placeRefuse
	// placeStale is a file with no markers that already carries a credentials
	// section in words that are not these: an earlier version's, or a copy
	// something reworded. placeWrap matches the text exactly and cannot take it,
	// and appending would leave two sections contradicting each other, so it is
	// named and left.
	placeStale
)

// placeSection reads that off the file, with the span the block replaces.
func placeSection(current []byte, section string) (sectionPlacement, int, int) {
	begin := bytes.Index(current, []byte(sectionBegin))
	end := bytes.Index(current, []byte(sectionEnd))
	switch {
	case begin >= 0 && end > begin:
		return placeReplace, begin, end + len(sectionEnd)
	case begin >= 0 || end >= 0:
		return placeRefuse, 0, 0
	}
	// Trimmed, so a file whose last line is the section's and which ends without
	// a newline still matches.
	body := strings.TrimRight(section, "\n")
	if at := bytes.Index(current, []byte(body)); at >= 0 {
		return placeWrap, at, at + len(body)
	}
	if carriesAStaleSection(current, body) {
		return placeStale, 0, 0
	}
	return placeAppend, 0, 0
}

// carriesAStaleSection reports whether an unmarked file already says what this
// section says, in words that are not these. The section's own heading and the
// tool's name, both: the heading alone is something an operator may write about
// their own credentials, and the name alone is a file that merely mentions
// faramir. Over-reporting costs a warning and one deletion; under-reporting
// costs two sets of instructions contradicting each other.
func carriesAStaleSection(current []byte, body string) bool {
	heading, _, ok := strings.Cut(body, "\n")
	if !ok || heading == "" {
		return false
	}
	if !bytes.Contains(current, []byte(heading+"\n")) {
		return false
	}
	return bytes.Contains(bytes.ToLower(current), []byte("faramir"))
}

// sectionBlock is the section between its markers, and carries no trailing
// newline: what surrounds it keeps its own, so writing twice over the same span
// yields the same bytes.
func sectionBlock(section string) string {
	return sectionBegin + "\n" + strings.TrimRight(section, "\n") + "\n" + sectionEnd
}

// writeSection returns the file with the block written where placeSection said.
func writeSection(current []byte, section string, place sectionPlacement, start, end int) []byte {
	block := sectionBlock(section)
	if place == placeReplace || place == placeWrap {
		// A fresh slice: the two appends below would otherwise write into the
		// caller's array.
		out := append([]byte{}, current[:start]...)
		out = append(out, block...)
		return append(out, current[end:]...)
	}
	return appendSection(current, block+"\n")
}

// appendSection adds the block to a file that has none, keeping what is there.
func appendSection(current []byte, block string) []byte {
	if len(bytes.TrimSpace(current)) == 0 {
		return []byte(block)
	}
	return append(append(bytes.TrimRight(current, "\n"), "\n\n"...), block...)
}

// sectionFile writes section into path between the markers, keeping everything
// outside them. head goes before the markers in a file this creates, for an
// agent that loads a file only where it carries one: Antigravity's rules take
// their activation from frontmatter. Every error it returns of its own leaves
// the file exactly as it was.
func (f fsys) sectionFile(path, section, head string, uid, gid int, within string) (bool, error) {
	// The mode for a file this creates. Not a parameter: there is one kind of
	// file here, and an existing one keeps its own below.
	mode := os.FileMode(instructionsMode)
	// A link followed and the owner checked; see fsys.editedFile.
	spot, err := f.editedFile(path, uid, within)
	if err != nil {
		return false, err
	}
	defer spot.close()
	if info := spot.info; info != nil {
		// Its own mode and its own owner: what faramir owns here is the block
		// between the markers rather than the file, and the block is
		// documentation. Sharing is told not to widen the instructions file so
		// that this command need not narrow it again.
		mode = info.Mode().Perm()
		uid, gid = ownerOf(info)
	}
	current, err := spot.read()
	switch {
	case err == nil:
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	default:
		return false, err
	}
	// What a file this creates opens with. Only where there is nothing there, an
	// existing file's first line staying its own.
	if head != "" && len(bytes.TrimSpace(current)) == 0 {
		current = []byte(head)
	}
	place, start, end := placeSection(current, section)
	switch place {
	case placeRefuse:
		return false, errHalfMarked
	case placeStale:
		return false, errStaleSection
	case placeAppend, placeReplace, placeWrap:
		// Every placement that writes.
	}
	return f.writeEdited(spot, writeSection(current, section, place, start, end), mode, uid, gid)
}

// sectionProblem is what an operator is told about a file that was left as it
// is. One wording per reason for both scopes, and each says what to do rather
// than only what happened.
func sectionProblem(err error, path, command string) string {
	switch {
	case errors.Is(err, errHalfMarked):
		return path + " carries faramir's section markers incompletely: " +
			sectionBegin + " and " + sectionEnd + ", in that order, are what delimit " +
			"the credentials section, and this file does not have both. Where the " +
			"section starts or stops cannot be read off it, so nothing was written. " +
			"Restore the markers around the section, or delete the one that is there, " +
			"and run " + command + " again"
	case errors.Is(err, errStaleSection):
		return path + " already carries a credentials section that is not between " +
			"markers and is not what is written now, so nothing was written: two sets " +
			"of credentials instructions in one file contradict each other. It may be " +
			"what an earlier version wrote, or your own notes. Delete it and run " +
			command + " again, which writes the current section between " +
			sectionBegin + " and " + sectionEnd + " so later runs can keep it current"
	case errors.Is(err, errNotOperators):
		return path + " is not the operator's, so nothing was written. This file is " +
			"one faramir edits rather than owns, and " + command + " runs as root: " +
			"editing somebody else's would be root writing a file it was never asked " +
			"to, and chowning it to make that true would take it from its owner. A " +
			"symlink here is followed, so this also names one landing on a file the " +
			"operator does not own, or on nothing at all. Give it to the operator, or " +
			"point the link at their own file, and run " + command + " again"
	}
	return err.Error()
}

// outOfDate reports whether an error left the section saying something other
// than what this version writes. Every error sectionFile returns of its own is
// one of these, and each leaves the file exactly as it was.
//
// Fatal in both commands: these files carry the policy an agent is held to, and
// a run that reports success having failed to update it leaves an operator
// believing a host says something it does not.
func outOfDate(err error) bool {
	return errors.Is(err, errHalfMarked) ||
		errors.Is(err, errStaleSection) ||
		errors.Is(err, errNotOperators)
}
