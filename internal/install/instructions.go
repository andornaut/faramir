package install

// The credentials instructions faramir writes into the prose a coding agent
// reads, at two scopes.  `init` writes the account-wide section into each
// agent's home instructions file, because the deny rules it installs there hold
// wherever the agent is working and arrive at the model as a bare refusal
// otherwise.  `init-project` writes the fuller section into the tree's, where
// there is a broker to name.
//
// Documentation, not enforcement: deleting either block changes nothing about
// what is reachable.

import (
	"bytes"
	"errors"
	"os"
	"strings"
)

// The markers delimiting a section, which is what makes a later run able to
// replace what an earlier one wrote.  Without them the only evidence is the
// section's own text, and a file that says the word "faramir" for any other
// reason then reads as a section that has drifted and is never updated again.
//
// A marker only helps while it survives, and these files are prose an operator
// edits and asks agents to rewrite; one that comes back with every word kept
// and an HTML comment dropped is ordinary.  That case is placeWrap rather than
// a reason to have no markers: what a stripped block leaves behind is the
// section's own text, which is enough to find it once and put the markers back.
const (
	sectionBegin = "<!-- BEGIN faramir: credentials -->"
	sectionEnd   = "<!-- END faramir: credentials -->"
)

// instructionsMode matches what the agent config files are written with, and is
// kept out of a shared tree for the same reason: see sharetree.Options.Keep.
const instructionsMode = 0o640

// The three files that are left alone.  Returned rather than repaired, so each
// caller can name the command that would write the section afresh.
var (
	// errHalfMarked is a file carrying one marker without the other.
	errHalfMarked = errors.New("the section markers are incomplete")
	// errStaleSection is a file with no markers already carrying a credentials
	// section in words that are not these.
	errStaleSection = errors.New("an undelimited credentials section is already there")
	// errSymlinked is a path that is a symlink.
	errSymlinked = errors.New("the instructions file is a symlink")
)

// Where a section goes, which is also what decides whether it can be written at
// all.
type sectionPlacement int

const (
	// placeAppend is a file with no block in it, and an empty or missing file.
	placeAppend sectionPlacement = iota
	// placeReplace is a file carrying both markers in order.  The span between
	// them is faramir's to rewrite whatever it now says, which is the point of
	// writing them.
	placeReplace
	// placeWrap is a file carrying the section's text and no markers, whether
	// they were never written or something tidied them out.  Wrapped where it
	// stands rather than appended, an append leaving the file with two
	// credentials sections.
	placeWrap
	// placeRefuse is one marker without the other, or an end before its begin.
	// Where the block starts or stops cannot be read off the file, and a guess
	// that is wrong rewrites somebody's prose.
	placeRefuse
	// placeStale is a file with no markers that already carries a credentials
	// section of faramir's in words that are not these: what a version whose
	// snippet read differently wrote, or a copy something reworded.  placeWrap
	// cannot take it, matching the text exactly, and appending would leave two
	// credentials sections contradicting each other.  So it is named and left,
	// and deleting it once is what puts the file under the markers for good.
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
// section says, in words that are not these.
//
// The section's own heading and the tool's name, both: the heading alone is
// something an operator may write about their own credentials, and the name
// alone is a file that merely mentions faramir, which is the case that must
// still get a section.  Together they are a copy of this one, reworded.
//
// Over-reporting costs a warning and one deletion.  Under-reporting costs a
// second set of credentials instructions contradicting the first, which is the
// outcome worth avoiding.
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
// outside them.  Shaped like writeFile, which it ends in.
//
// Every error it returns of its own leaves the file exactly as it was.
func (f fsys) sectionFile(path, section string, mode os.FileMode, uid, gid int) (bool, error) {
	// Never through a link.  These are the operator's own prose, and a dotfiles
	// manager keeps such a file as a link into a repository it owns; writeFile
	// renames a new file over the path, which would leave a regular file where
	// the link was and the repository's copy stale and no longer read.  Refused
	// rather than followed, for the reason ensureDir and ensureOwnership refuse
	// one: what is on the other end is not this command's to decide.
	switch link, err := os.Lstat(path); {
	case err == nil && link.Mode()&os.ModeSymlink != 0:
		return false, errSymlinked
	case errors.Is(err, os.ErrNotExist):
	// A dry run is the one form that does not need root, so a file it cannot
	// look at is reported as no change rather than stopping the run, as
	// ensureDir and ensurePrivateFile do.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case err != nil:
		return false, err
	}
	current, err := os.ReadFile(path)
	switch {
	case err == nil, errors.Is(err, os.ErrNotExist):
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	default:
		return false, err
	}
	place, start, end := placeSection(current, section)
	switch place {
	case placeRefuse:
		return false, errHalfMarked
	case placeStale:
		return false, errStaleSection
	}
	return f.writeFile(path, writeSection(current, section, place, start, end), mode, uid, gid)
}

// sectionWarning is what an operator is told about a file that was left as it
// is.  One wording per reason for both scopes, the file being the same kind of
// thing either way, and each says what to do rather than only what happened.
func sectionWarning(err error, path, command string) string {
	switch {
	case errors.Is(err, errHalfMarked):
		return path + " carries faramir's section markers incompletely: " +
			sectionBegin + " and " + sectionEnd + ", in that order, are what delimit " +
			"the credentials section, and this file does not have both. Where the " +
			"section starts or stops cannot be read off it, so it was left as it is. " +
			"Restore the markers around the section, or delete the one that is there " +
			"and run " + command + " to have the section written afresh"
	case errors.Is(err, errStaleSection):
		return path + " already carries a credentials section that is not between " +
			"markers and is not what is written now, so it was left as it is and " +
			"nothing was added: two sets of credentials instructions in one file " +
			"contradict each other. It may be what an earlier version wrote, or your " +
			"own notes. Delete it and run " + command + ", which writes the current " +
			"section between " + sectionBegin + " and " + sectionEnd + " so later runs " +
			"can keep it up to date"
	case errors.Is(err, errSymlinked):
		return path + " is a symlink, so it was left as it is: writing the " +
			"credentials section would replace the link with a regular file and leave " +
			"whatever it points at unread. Add the section to the file it points at, " +
			"or replace the link with a regular file and run " + command
	}
	return err.Error()
}

// leftAlone reports whether an error is one of sectionFile's own, which leave
// the file untouched and are warned about rather than fatal: the deny rules are
// the enforcement, and what is missing is the paragraph explaining them.
func leftAlone(err error) bool {
	return errors.Is(err, errHalfMarked) ||
		errors.Is(err, errStaleSection) ||
		errors.Is(err, errSymlinked)
}
