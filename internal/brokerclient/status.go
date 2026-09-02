package brokerclient

// The two ops a command asks of a broker that may not be there: what it is,
// and whether it will re-read the store. Both answer a zero value on a broker
// that did not answer, every caller having something to fall back on, and
// both dial for less than a round trip allows: a broker that is not running is
// the ordinary case on a host being provisioned, and neither may make a
// command feel slow.

import (
	"encoding/json"
	"path/filepath"
	"time"
)

// quickDial is how long a caller that can proceed without the broker waits
// for one to pick up.
const quickDial = 2 * time.Second

// OpStatus is the wire name of the status op and the command name both.
const OpStatus = "status"

// Status is what a running broker says about itself: where its config is, and
// which build is answering.
type Status struct {
	ConfigDir string
	Version   string
	// Build is which build of that version, for the versions that do not name
	// one. Empty from a release, and from a broker of a build that predates it.
	Build string
}

// AskStatus asks a running broker about itself in one round trip, and returns
// a zero Status on any failure.
func AskStatus(socketPath string) Status {
	line, err := roundTrip(socketPath, map[string]any{"op": OpStatus}, quickDial, 5*time.Second)
	if err != nil {
		return Status{}
	}
	// The status body is itself JSON, carried as the response's output string.
	var response struct {
		Output  string `json:"output"`
		Version string `json:"version"`
		Error   *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return Status{}
	}
	// A broker of another release refuses this before it reads the op, so the
	// refusal is the answer: what refused names the build that is running, and
	// there is no status body to read. Reported as skew rather than as a broker
	// that said nothing.
	if response.Error != nil {
		return Status{Version: response.Version}
	}
	var body struct {
		Config  string `json:"config"`
		Version string `json:"version"`
		Build   string `json:"build"`
	}
	if err := json.Unmarshal([]byte(response.Output), &body); err != nil {
		return Status{}
	}
	out := Status{Version: body.Version, Build: body.Build}
	if body.Config != "" {
		out.ConfigDir = filepath.Dir(body.Config)
	}
	return out
}

// RefreshOK is what Refresh returns when the broker re-read the store: a
// sentinel rather than a bool, so the refusals it can answer with are carried
// back with it.
const RefreshOK = "ok"

// refreshWait covers one decrypt of the whole store, which is what the broker
// does before it answers.
const refreshWait = 2 * time.Minute

// Refresh asks the running broker to re-read the managed store now, and
// reports whether it did: RefreshOK, the broker's refusal, or "" where nothing
// answered.
//
// Called by the commands that write the store. Without it a value stays outside
// the redactor until the refresh interval comes round, and a command run in
// that window prints it in the clear, which is what an operator does
// immediately after rotating one to see that it took.
//
// Not fatal when it does not land: the file is written either way, and a broker
// that is not running, is mid-restart, or is an older build that does not know
// the op is not a reason to call the write a failure. It is not silent either.
// The caller says what happened, because "the broker has re-read it" on a host
// where nothing answered is the sentence that sends somebody to run the command
// this exists to make safe.
func Refresh(socketPath string) string {
	// The answer is read rather than closed on: the refresh runs while the
	// broker is answering, so returning before it lands would leave the same
	// window this exists to close, just a shorter one. And the answer is what
	// says it landed: an older broker refuses the op it does not know.
	line, err := roundTrip(socketPath, map[string]any{"op": "refresh"}, quickDial, refreshWait)
	if err != nil {
		return ""
	}
	var reply struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		return ""
	}
	if reply.Error != nil {
		// A broker that answered and said no. The commonest is version skew, the
		// binary having been replaced before the daemon was restarted, and
		// reporting that as silence sends an operator to look at a daemon that is
		// answering.
		return reply.Error.Message
	}
	return RefreshOK
}
