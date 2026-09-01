package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// opStatus answers what the broker loaded and what it can reach. Non-zero
// wherever the store is degraded, the body still printed: a ref the config names
// and the broker cannot answer is a host that is not what its config describes,
// and without an exit code to read, the first sign of it is a command failing
// later. Store.Degraded is the whole of that question; `faramir doctor` answers
// the same one and says what to do about each.
func (s *Server) opStatus() protocol.Response {
	// Whether, never a value: any member of the client group can ask, including
	// the coding agent, so what goes here lands in a model's context. It is also
	// the whole answer, a configured key that did not load looking identical to a
	// working one from the config's side.
	//
	// Describe carries the store's patterns and resolved files, which is where
	// rather than whether, and deliberately so: the config path below is 0644 and
	// its [secret] patterns already name the directory, so the file list is which
	// of those globs matched, not anything the agent could not already reach.
	configured, usable := s.Config.Ssh.Key != "", false
	if configured {
		data, err := os.ReadFile(s.Config.Ssh.Key)
		usable = err == nil && unusableReason(data) == ""
	}
	// Why the exit status below is what it is. Counted, never named: a ref in no
	// redactor is a value nothing tokenizes, and its name is what would make it
	// worth targeting. Empty on a store doing its whole job, so the field is
	// there either way and a caller reads one thing rather than inferring from a
	// status code with nothing beside it.
	document := map[string]any{
		"version": version.Version,
		// Which build, for the versions that do not name one. Empty for a
		// release, where the version is the answer.
		"build": version.Build,
		// The config file this broker loaded.
		"config":  s.Config.Path,
		"secrets": s.Store.Describe(),
		"ssh":     map[string]any{"configured": configured, "usable": usable},
		// Whether a brokered command may ask to sudo, which the agent needs to
		// know: without it a playbook touching this host has to leave it out.
		// Whether, not how.
		"sudo": map[string]any{"enabled": s.Escalation.Enabled()},
		// Named apart from secrets.errors, which is what a managed file said when
		// it did not load: this is every state that leaves a configured ref not
		// working or a configured value uncovered, which is the wider question.
		"degraded": s.Store.DegradedCounts(),
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return protocol.ErrorResponse("internal", "the status could not be "+
			"rendered: "+err.Error(), "")
	}
	code := 0
	if s.Store.Degraded() != "" {
		code = 1
	}
	return okResponse(code, string(body)+"\n")
}

// opRefresh re-reads the managed store now. Root's, because it is the operator
// commands that write the store: an agent asking would only be asking the
// broker to do sooner what it does on the interval anyway, at the cost of a
// decrypt per request.
//
// What it buys is the window between writing a value and the broker holding it,
// where the new value is in no redactor and a command that prints it prints it.
// `faramir vault` closes that itself rather than leaving it to the clock.
func (s *Server) opRefresh(peer *sockutil.Peer) protocol.Response {
	if peer == nil || peer.UID != 0 {
		return protocol.ErrorResponse("forbidden",
			"refresh is root's: it is what writes the managed store that asks for "+
				"it, and everything else is served by the refresh interval", "")
	}
	if !s.Store.Refresh(refreshWait) {
		// A reload already under way that did not finish in time. Refused rather
		// than answered, so the caller reports the interval it is now waiting on
		// instead of telling an operator the store has been re-read.
		return protocol.ErrorResponse("busy", fmt.Sprintf(
			"a reload was already running and did not finish within %s, so this "+
				"did not re-read the store; the refresh interval covers it", refreshWait), "")
	}
	refs := s.Store.Refs()
	response := okResponse(0, "")
	response["refs"] = refs
	return response
}

// refreshWait bounds what the refresh op waits for a reload already in flight.
// Under the caller's own deadline, so a caller that gives up first is the
// unusual case rather than the ordinary one.
const refreshWait = 90 * time.Second

func (s *Server) opListSecrets() protocol.Response {
	// Names only, and only refs that loaded: a value the redactor cannot cover is
	// refused at load.
	refs := s.Store.Refs()
	var output strings.Builder
	for _, ref := range refs {
		output.WriteString("faramir://" + ref + "\n")
	}
	response := okResponse(0, output.String())
	response["refs"] = refs
	return response
}
