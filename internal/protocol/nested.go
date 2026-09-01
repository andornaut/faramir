package protocol

import "os"

// NestedRun is why a nested `faramir run` cannot be expected to work here, and
// "" where it can. Kept beside the calls that make one rather than beside any
// one command, so a command that starts shelling back later inherits the
// answer instead of meeting the bare refusal.
//
// $FARAMIR_OPERATOR is the marker: the broker puts it in every brokered
// command's environment, and the sudo grant's env_file carries it through to
// root, which is what makes it readable from here.
func NestedRun() string {
	if os.Getenv(OperatorEnv) == "" {
		return ""
	}
	return "this is running inside a brokered command (" + OperatorEnv +
		" is set), which already holds the escalation that got it to root, and no " +
		"second brokered command runs while one is held"
}
