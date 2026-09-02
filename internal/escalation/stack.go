package escalation

// Where the stack that decides an escalation lives.
//
// Not one answer, because the two sudo implementations do not agree on how a
// PAM service is chosen. The original is sent to a service of faramir's own by
// the grant's `pam_service`, so the stack is that service's file. sudo-rs has no
// such setting and reaches the service named `sudo` for everybody, so it can be
// sent nowhere: there the stack is a delimited block spliced into the files it
// does read, and no service file exists at all.
//
// Both the installer that writes it and the broker that checks a host can answer
// an escalation have to recognise the same block, which is why the markers are
// named here rather than in either of them.

import (
	"fmt"
	"os"
	"strings"
)

// The markers delimiting faramir's block in a shared stack.
const (
	BlockBegin = "# BEGIN faramir"
	BlockEnd   = "# END faramir"
)

// PamDir is where the distribution keeps PAM's service files, and the default
// every caller starts from. Taken as a parameter below rather than read as a
// global: the installer redirects it to a temporary directory under test, and a
// second mutable copy of it is how one of the two ends up being moved while the
// code reads the other.
const PamDir = "/etc/pam.d"

// sharedStacks are the stacks every account's sudo reads, one per launch type:
// `sudo` for a command and `sudo-i` for a login shell.
func sharedStacks(pamDir string) []string {
	return []string{pamDir + "/sudo", pamDir + "/sudo-i"}
}

// Stack is the file carrying the stack a brokered command's sudo authenticates
// against, preferring what the install recorded.
//
// recorded is [sudo] pam_stack, which says which arrangement this host is
// in and is the whole answer where it is set and the file is there. Empty in a
// config written before that key existed, and wrong on a host somebody has since
// rearranged, so a miss falls through to looking for either arrangement rather
// than reporting a host as broken on the strength of a stale path.
func Stack(pamDir, recorded, pamService string) (string, error) {
	if recorded != "" {
		if _, err := os.Stat(recorded); err == nil {
			return recorded, nil
		}
	}
	return StackFile(pamDir, pamService)
}

// StackFile is the file carrying the stack a brokered command's sudo
// authenticates against, found by looking rather than by being told, or an error
// naming what is absent.
//
// A host with neither arrangement is one where sudo falls back to PamDir/other,
// which asks for a password nothing supplies.
func StackFile(pamDir, pamService string) (string, error) {
	own := pamDir + "/" + pamService
	if _, err := os.Stat(own); err == nil {
		return own, nil
	}
	for _, path := range sharedStacks(pamDir) {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if hasBlock(string(body)) {
			return path, nil
		}
	}
	return "", fmt.Errorf("there is no %s and no faramir block in %s", own,
		strings.Join(sharedStacks(pamDir), " or "))
}

// hasBlock reports whether a stack carries a whole faramir block. Both markers,
// each a line of its own: one without the other is a file something edited, and
// not a stack this can answer for.
func hasBlock(body string) bool {
	var begin, end bool
	for line := range strings.Lines(body) {
		switch strings.TrimSpace(line) {
		case BlockBegin:
			begin = true
		case BlockEnd:
			end = true
		}
	}
	return begin && end
}
