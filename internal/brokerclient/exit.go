package brokerclient

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

// UnavailableError is a broker socket that could not be dialled, told apart so
// a caller can exit ExitUnavailable. The message is the dial's own.
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string { return e.Err.Error() }
func (e *UnavailableError) Unwrap() error { return e.Err }
