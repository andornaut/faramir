package brokerclient

import "errors"

// The exit statuses the CLI gives other than 0 and 1, named once so every
// command gives the same one for the same condition.
const (
	// ExitUnavailable is EX_UNAVAILABLE: the broker could not be reached, or
	// did not answer.
	ExitUnavailable = 69
	// ExitTempFail is EX_TEMPFAIL: the broker was at its concurrency limit, and
	// the same request succeeds a moment later.
	ExitTempFail = 75
	// ExitNotExecutable and ExitNotFound are the shell's: a program that is
	// there and cannot be run, and one that is not there.
	ExitNotExecutable = 126
	ExitNotFound      = 127
)

// UnavailableError is a broker that could not be reached or did not answer,
// told apart from one that answered with a refusal so a caller can exit
// ExitUnavailable for the one and not the other. The message is the
// underlying error's own.
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string { return e.Err.Error() }
func (e *UnavailableError) Unwrap() error { return e.Err }

// FailureCode is the status a failed broker request exits with:
// ExitUnavailable for a broker that could not be reached or did not answer, as
// `faramir run` and `faramir refs` give, and 1 for anything else, a refusal or
// a reply that did not parse among them.
func FailureCode(err error) int {
	if _, ok := errors.AsType[*UnavailableError](err); ok {
		return ExitUnavailable
	}
	return 1
}
