package install

// Whether this process is itself inside a brokered command, which decides what
// the calls that shell back into the broker can expect.
//
// Four places run `faramir run` to ask something only a brokered command can
// answer: init's validate step and three of doctor's checks. Inside a brokered
// command every one of them is refused, the outer command holding the
// escalation that got this process to root and no second brokered command
// running while one is held. The refusal is correct and says so, but it names
// the lock rather than the nesting, and nothing in it points at the cause.

import (
	"os"

	"github.com/andornaut/faramir/internal/protocol"
)

// NestedRun is why a nested `faramir run` cannot be expected to work here, and
// "" where it can. Kept beside the calls that make one rather than beside any
// one command, so a command that starts shelling back later inherits the
// answer instead of meeting the bare refusal.
//
// $FARAMIR_OPERATOR is the marker: the broker puts it in every brokered
// command's environment, and the sudo grant's env_file carries it through to
// root, which is what makes it readable from here.
func NestedRun() string {
	if os.Getenv(protocol.OperatorEnv) == "" {
		return ""
	}
	return "this is running inside a brokered command (" + protocol.OperatorEnv +
		" is set), which already holds the escalation that got it to root, and no " +
		"second brokered command runs while one is held"
}
