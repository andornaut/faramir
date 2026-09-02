package auditview

// The one-line summary and the outcome column.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termuitest"
)

func TestSummariseReportsWhatRanAndHowItEnded(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf00a91f","op":"run",`+
		`"cmd":["ansible-playbook","msmtp.yml"],"exit_code":0,"duration_sec":1.5,`+
		`"redactions":[{"token":"«SECRET:a»","count":2}]}`), termuitest.Plain(t))
	// The whole id, which is what a lookup takes: asserting on its tail would
	// pass a row that printed only the tail.
	for _, want := range []string{"w5vq7dbf00a91f", "run", "exit 0", "1.50s", "2 redacted",
		"ansible-playbook msmtp.yml"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary is missing %q: %s", want, line)
		}
	}
}

// A redact runs no command, so it has no exit code, but the row still has to
// say something.
func TestSummariseSaysSomethingForARedact(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf00b1c2","op":"redact","input_bytes":1447,`+
		`"redactions":[{"token":"«SECRET:a»","count":1}]}`), termuitest.Plain(t))
	if strings.Contains(line, "exit") {
		t.Errorf("a record that ran nothing was given an exit: %s", line)
	}
	for _, want := range []string{"1 redacted", "1.4 KiB in"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary is missing %q: %s", want, line)
		}
	}
}

// A timed-out command's exit code says nothing useful.
func TestOutcomeReportsATimeout(t *testing.T) {
	label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":0,"timed_out":true}`))
	if label != "timed out" || !failed {
		t.Errorf("outcome = (%q, %v), want (timed out, true)", label, failed)
	}
}

// A run killed because its caller went. The record is the whole of what is
// reported -- the response went to a connection that had closed -- and read as
// a bare "exit 137" it says a signal without saying who sent it, which is the
// one thing this row is for.
func TestOutcomeReportsACallerThatWent(t *testing.T) {
	label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":137,"abandoned":true}`))
	if label != "caller gone" || !failed {
		t.Errorf("outcome = (%q, %v), want (caller gone, true)", label, failed)
	}
	// And a timeout is still a timeout: both end in a killed process, and only
	// one of them is the command taking too long.
	label, _ = outcome(rec(t, `{"log_id":"x","op":"run","exit_code":137,"timed_out":true}`))
	if label != "timed out" {
		t.Errorf("outcome = %q, want timed out", label)
	}
	// An ordinary ending is untouched.
	if label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":0}`)); failed ||
		!strings.Contains(label, "0") {
		t.Errorf("outcome = (%q, %v), want a clean exit", label, failed)
	}
}

// A refused request never reached a command, so it has no exit code. The
// listing has to say so: the alternative renders it as a command that ran and
// produced nothing, which is a different event.
func TestOutcomeReportsTheRefusalCode(t *testing.T) {
	for _, code := range []string{"bad_request", "unknown_secret", "busy",
		"forbidden", "no_secrets", "too_large", "not_quiescent", "no_audit"} {
		record := rec(t, `{"log_id":"x","op":"run","cmd":["/bin/true"],`+
			`"refused":"`+code+`","error":"why"}`)
		label, failed := outcome(record)
		if label != code || !failed {
			t.Errorf("outcome = (%q, %v), want (%s, true)", label, failed, code)
		}
		// The code is what the caller was answered with, so the row can be
		// scanned for it and matched against what the agent reported.
		if line := summarise(record, termuitest.Plain(t)); !strings.Contains(line, code) {
			t.Errorf("the listing does not name the refusal: %s", line)
		}
	}
}

// The broker also records a request that failed without being refused: the
// program would not resolve, or the executor was lost after the child was
// spawned. Neither carries an exit code either.
func TestOutcomeReportsAFailureWithNoExitCode(t *testing.T) {
	for _, body := range []string{
		`{"log_id":"x","op":"run","cmd":["/bin/nope"],"error":"no such program"}`,
		`{"log_id":"x","op":"run","cmd":["/bin/sh"],"started_at":1786000000,` +
			`"error":"executor: connection reset"}`,
	} {
		label, failed := outcome(rec(t, body))
		if label != "failed" || !failed {
			t.Errorf("outcome = (%q, %v), want (failed, true): %s", label, failed, body)
		}
	}
}

// A record that ran keeps its exit code, and a redact has no outcome at all:
// neither is what the two branches above are for.
func TestOutcomeLeavesTheOrdinaryRecordsAlone(t *testing.T) {
	label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":0,"duration_sec":1}`))
	if label != "exit 0 1.00s" || failed {
		t.Errorf("outcome = (%q, %v), want (exit 0 1.00s, false)", label, failed)
	}
	if label, failed := outcome(rec(t, `{"log_id":"x","op":"redact","input_bytes":10}`)); label != "" || failed {
		t.Errorf("a redact was given an outcome: (%q, %v)", label, failed)
	}
}

// Padding counts escape bytes as width.
func TestPaintOutcomePadsBeforeColouring(t *testing.T) {
	record := rec(t, `{"log_id":"x","op":"run","exit_code":0}`)
	got := paintOutcome(record, termuitest.Always(t))
	if !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("padding landed outside the colour span: %q", got)
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(got, "\x1b[32m"), "\x1b[0m")
	if len(bare) != len(paintOutcome(record, termuitest.Plain(t))) {
		t.Errorf("coloured field is a different width from the plain one: %q", got)
	}
}

// An op longer than its column must not run into the one after it: merged as
// `run_startedstarted`, with every column past it shifted, the row is read
// wrong.
func TestSummariseKeepsTheColumnsApartForALongOp(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf004e16","op":"run_started",`+
		`"approved":false,"cmd":["sudo","id","-un"]}`), termuitest.Plain(t))
	if strings.Contains(line, "run_startedstarted") {
		t.Errorf("op and outcome merged: %q", line)
	}
	if !strings.Contains(line, "run_started started") {
		t.Errorf("summarise = %q, want the op and the outcome as separate columns", line)
	}
}

// The same for the outcome column, which holds a refusal code and so can be
// wider than the column: escalation_in_progress is 20 against a 16-wide column.
// The row shifts, which is legible; the columns merging is not.
func TestSummariseKeepsTheColumnsApartForALongRefusalCode(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf004e16","op":"run",`+
		`"refused":"escalation_in_progress","cmd":["sudo","id","-un"]}`), termuitest.Plain(t))
	if !regexp.MustCompile(`escalation_in_progress +sudo id -un`).MatchString(line) {
		t.Errorf("summarise = %q, want the code and the command as separate columns", line)
	}
}

// A command that has started and not ended reads as started. Blank in that
// column would render it as a command that ran and did nothing, which is the one
// reading the listing must not offer, and "running" would claim of a log read
// later that the command is still going.
func TestAStartedExecReadsAsStarted(t *testing.T) {
	label, failed := outcome(map[string]any{"op": "run_started", "cmd": []any{"playbook"}})
	if label != "started" {
		t.Errorf("outcome = %q, want started", label)
	}
	if failed {
		t.Error("a command that has only started is painted as a failure")
	}
}

// A question a human refused was judged; one that expired means nothing was
// watching. Rendered alike they read as the same event, and an operator scanning
// for "nobody was there" would find neither.
func TestEachAnswerReadsAsItsOwnEnding(t *testing.T) {
	for _, tc := range []struct {
		code   string
		want   string
		failed bool
	}{
		{escalation.CodeApproved, "approved", false},
		{escalation.CodeRejected, "rejected", true},
		{escalation.CodeExpired, "timed out", true},
		{escalation.CodeNotQuiescent, "not quiescent", true},
		{escalation.CodeRunEnded, "run ended", true},
		{escalation.CodeBrokerStopped, "broker stopped", true},
		// A code this reader does not know is printed rather than blanked: the log
		// is read by whatever version is installed, and a row saying nothing about
		// how a question ended is the one thing this column must not print.
		{"something_later", "something_later", true},
	} {
		t.Run(tc.code, func(t *testing.T) {
			label, failed := outcome(map[string]any{
				"op": "escalate", "approved": tc.code == escalation.CodeApproved,
				"outcome_code": tc.code, "outcome": "prose nobody selects on",
			})
			if label != tc.want {
				t.Errorf("outcome = %q, want %q", label, tc.want)
			}
			if failed != tc.failed {
				t.Errorf("failed = %v, want %v", failed, tc.failed)
			}
		})
	}
}

// A record written before the code existed still reads: the boolean is what it
// carried, and a listing over a log that spans an upgrade must not blank half of
// its rows.
func TestAnAnswerWithNoCodeStillReads(t *testing.T) {
	if label, failed := outcome(map[string]any{
		"op": "escalate", "approved": false, "outcome": "refused by root",
	}); label != "rejected" || !failed {
		t.Errorf("outcome = (%q, %v), want (rejected, true)", label, failed)
	}
}
