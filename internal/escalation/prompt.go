package escalation

// The question a human is shown: the run it names, the command rendered so a
// terminal cannot be driven by it, and the id an answer refers to.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/termsafe"
)

// Run is the brokered command a request is made on behalf of. Naming it is
// what makes the answer worth anything: an approval the human cannot attribute
// to a command they initiated grants root to whatever asked.
type Run struct {
	// Argv is the command the broker started, already redacted: a caller can put
	// a value in argv even though the broker never does, and this reaches a
	// terminal and the audit log.
	Argv []string
	Cwd  string
	// Argv0Path is what the broker resolved Argv[0] to, and so the program root
	// will actually run. A relative Argv[0] resolves against the request's cwd,
	// which is the agent's working tree, so the two can name different files.
	Argv0Path string
	// LogID is the exec record this belongs to, so the log reads in both
	// directions: what a command was approved for, and what an approval was
	// spent on.
	LogID string
	// Caller is the account that asked for the command, which is not the one that
	// would run it: every brokered command runs as the executor, and more than
	// one account can be in the client group.
	Caller string

	// approved is set once a human has said yes to this run, and is what makes
	// the rest of its sudos free of a second question. Not exported: a caller
	// registering a run pre-approved would be an escalation nobody answered.
	approved bool

	// refusedCode and refusedReason are the last no this run was given, kept so
	// the broker can say why the command failed: a refusal and an expiry both
	// reach the caller as sudo's own authentication failure, and which one it was
	// decides whether running it again is worth anything.
	refusedCode   string
	refusedReason string

	// waited is how long this run's questions have held it, and waitingSince is
	// when the one outstanding began, zero where none is. Duration is wall time
	// from fork to exit, so without this a slowly answered question reads as a
	// slow command. The question's lifetime rather than each sudo's own wait,
	// which would double-count a sudo that joined a question another raised.
	waited       time.Duration
	waitingSince time.Time
}

// resolvedProgram is what argv[0] resolved to when that is not what argv[0]
// says, and "" when the two agree.
func (r Run) resolvedProgram() string {
	if len(r.Argv) == 0 || r.Argv0Path == "" || r.Argv0Path == r.Argv[0] {
		return ""
	}
	return r.Argv0Path
}

// maxCommandChars bounds what a question spends on the command. Argv is the
// caller's and can be as long as it likes; a question whose content has
// scrolled off the top of a terminal is one nobody read. The audit record
// keeps the whole of it.
const maxCommandChars = 240

// Command is the run as one line, rendered for a terminal. Every string in it
// is the caller's and reaches the operator through `faramir sudo ls`, the
// refusal messages and [sudo] notify_command, so left raw a run could
// return the cursor with a "\r" and overwrite the question it is judged on.
// termsafe says what survives that rendering.
func (r Run) Command() string {
	parts := make([]string, 0, len(r.Argv))
	for _, arg := range r.Argv {
		parts = append(parts, termsafe.Arg(arg))
	}
	return termsafe.Bound(strings.Join(parts, " "), maxCommandChars)
}

// safeField is termsafe.Field at this package's bound, for one field of a
// question rather than one argument of a command.
func safeField(value string) string { return termsafe.Field(value, maxCommandChars) }

// safeComposed is for a field the broker wrote rather than took from a caller:
// escaped and bounded like the rest, and not quoted. safeField quotes anything
// holding a space, which is noise around the broker's own words.
func safeComposed(value string) string {
	if value == "" {
		return ""
	}
	return termsafe.Bound(termsafe.Line(value), maxCommandChars)
}

// safeUnlessEmpty is safeField for a field a caller drops when it is absent.
func safeUnlessEmpty(value string) string {
	if value == "" {
		return ""
	}
	return safeField(value)
}

// newID names a question in something a person can type: it is read off one
// terminal and typed into another, and only one question is outstanding at a
// time. Empty when there is no randomness, and the caller then refuses the
// request rather than substituting a constant.
func newID() string {
	var raw [3]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

// Prompt is what the human is asked: one line and the command, so the answer
// means something. The host, the cwd and the resolved program are fields of the
// Question, printed under it. Exported so a test, the CLI and the notifier
// agree on it.
func Prompt(run Run) string {
	return fmt.Sprintf("%s `%s`", PromptPrefix, run.Command())
}

// PromptPrefix is the question without the command, for the terminal that
// prints the command on a line of its own below it. The notifier gets the
// whole sentence, having no second line to put one on.
const PromptPrefix = "faramir: Approve this command to run as root?"

// hostname is what the question says it is about, and never empty: a question
// that names no host is one an operator watching two of them cannot place.
func hostname() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "this host"
	}
	return safeField(host)
}

func (s *Server) record(entry map[string]any) {
	if s.Record != nil {
		s.Record(entry)
	}
}

// --------------------------------------------------------------------------
// The answer channel (reached through the broker socket, root only)
// --------------------------------------------------------------------------
