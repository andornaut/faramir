package broker

import (
	"fmt"
	"log"
	"os/user"
	"strconv"
	"strings"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

// refuseUnreadable is the gate on the two ops whose output is redacted against
// the value set; see Store.Unreadable. Asked here rather than at startup: a
// startup check judges the host as it was at boot, and exiting would take the
// daemon down just when `faramir status` and `doctor` would explain why.
// status and refs stay available, neither producing output that depends on the
// set.
func (s *Server) refuseUnreadable(op, phrase, logID string, peer *sockutil.Peer) *protocol.Response {
	reason := s.Store.Unreadable()
	if reason == "" {
		return nil
	}
	log.Printf("%s refusing %s: %s", logID, phrase, reason)
	// Recorded like a served call: a refusal is what the operator is looking for
	// when they ask why nothing ran.
	s.Audit.Write(map[string]any{
		"log_id": logID, "op": op, "refused": "no_secrets", "reason": reason,
		// Who was refused, as every other record carries it. Without it this is
		// the one refusal in the log that says what happened and not to whom, and
		// a store that cannot be read produces a run of them.
		"peer": peer,
	}, audit.Output{})
	// The remedies are for the states that reach here, which are a managed file
	// that was found and did not load, and a keeper that never answered. A store
	// nobody has written yet is not one of them: Store.Unreadable serves that
	// case rather than refusing it, so advice about writing a first file was
	// advice for a condition this message cannot carry.
	out := protocol.ErrorResponse("no_secrets", fmt.Sprintf(
		"the broker does not hold every managed value, so %s would run with "+
			"less redaction than the config asks for: %s. `sudo faramir doctor` "+
			"says what to do about each file named above; a file the keeper "+
			"cannot decrypt usually has the wrong age key or recipients. If the "+
			"reason names a [[secret.link]] ref, that link claims a name the managed "+
			"store already defines; `sudo faramir link rm REF` removes it",
		phrase, reason), logID)
	return &out
}

// refuse answers a request that will not run, and records it under the log_id
// the caller is given: `faramir run` prints that id, so one naming
// no record sends somebody to look up nothing. Not for the refusals decided
// before a request is parsed -- too_large, a forbidden peer, malformed JSON --
// which carry no id.
func (s *Server) refuse(code, message, logID string, peer *sockutil.Peer,
	cmd []string, cwd string) protocol.Response {
	record := s.redactor()
	detail := record.RedactText(message)
	entry := map[string]any{
		"log_id": logID, "op": recordRun, "peer": peer,
		"refused": code, "error": detail,
	}
	if len(cmd) > 0 {
		entry["cmd"] = redactEach(record, cmd)
	}
	if cwd != "" {
		entry["cwd"] = record.RedactText(cwd)
	}
	s.Audit.Write(entry, audit.Output{})
	return protocol.ErrorResponse(code, detail, logID)
}

// privateTmpDirs is what PrivateTmp= gives every unit its own copy of, so a path
// under one is the daemon's and not the caller's. These two and no others:
// /dev/shm is shared with the caller, which is why a brokered command's
// leavings there are the caller's to find. Must agree with install.privateTmp,
// which is the same list for the install's own purposes.
var privateTmpDirs = []string{"/tmp", "/var/tmp"}

// cwdMissing explains a working directory the broker cannot find, and names the
// one reason it goes missing while the caller is looking straight at it: every
// faramir unit runs with PrivateTmp=true, so the daemon's /tmp and /var/tmp are
// its own and hold nothing the caller put there.
//
// Without this the message is "cwd does not exist" about a directory the caller
// just made and can list, which reads as a bug in the broker rather than as the
// boundary it is. Scratch under /tmp is the obvious place to put a working
// directory, so this is met by anyone who tries it.
func cwdMissing(cwd string) string {
	for _, private := range privateTmpDirs {
		if cwd != private && !strings.HasPrefix(cwd, private+"/") {
			continue
		}
		return "cwd does not exist for this daemon: " + cwd + ". Every faramir unit " +
			"runs with PrivateTmp=true, so " + private + " here is the daemon's own " +
			"and holds nothing you put in yours. Name a directory outside " +
			strings.Join(privateTmpDirs, " and ") + "."
	}
	return "cwd does not exist: " + cwd
}

// refuseUnauditable is the gate on running anything at all: a command that
// cannot be recorded is not run, and the agent can reach that state by printing
// enough to fill the filesystem. Nothing is recorded here, there being nowhere
// to record it: the refusal goes back to the caller and to the daemon log.
func (s *Server) refuseUnauditable(phrase, logID string) *protocol.Response {
	reason := s.Audit.Unwritable()
	if reason == "" {
		return nil
	}
	log.Printf("%s refusing %s: the audit log cannot be written: %s", logID, phrase, reason)
	out := protocol.ErrorResponse("no_audit",
		"the audit log cannot be written ("+reason+"), so "+phrase+" was refused: "+
			"a command that cannot be recorded does not run. Free space on that "+
			"filesystem, or point [audit] log_path at one with room, and retry", logID)
	return &out
}

// callerName renders the peer as a person reads it: the name where the account
// still exists, and the uid either way, a name being reusable and an account
// removable while a question is still on somebody's screen.
func callerName(peer *sockutil.Peer) string {
	if peer == nil {
		return ""
	}
	if entry, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		return fmt.Sprintf("%s (uid %d)", entry.Username, peer.UID)
	}
	return fmt.Sprintf("uid %d", peer.UID)
}
