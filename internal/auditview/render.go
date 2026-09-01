package auditview

// One record as one line: the summary a listing shows, and the outcome
// colouring that says how a run ended.

import (
	"fmt"
	"strings"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termsafe"
	"github.com/andornaut/faramir/internal/termui"
)

// logIDWidth is what audit.NewLogID mints plus the separating space, sized past
// the id rather than to it; see opWidth.
const logIDWidth = 15

// OpWidth is the longest op recorded, `run_started` at eleven, plus the
// separating space. Sized past the longest rather than to it: pad appends a
// space to anything already at the width, so a column exactly as wide as its
// longest value puts every following column of that row somewhere else.
const OpWidth = 12

// OpRunStarted is the first half of the pair a run writes, and the one record
// with no ending in it. Named here as well as at the broker that writes it:
// this reader is pointed at a file, not linked to the daemon.
const OpRunStarted = "run_started"

// OpEdit and OpReseal are what the edit and reseal commands record.
const (
	OpEdit   = "edit"
	OpReseal = "reseal"
)

// Summarise is one record on one line: when, what, how it ended, how many
// values it touched, and the id to ask for the rest. The id is printed whole,
// which is what a lookup takes.
func Summarise(record map[string]any, paint termui.Palette) string {
	var b strings.Builder
	b.WriteString(paint.Dim(Pad(Str(record, "log_id"), logIDWidth)))
	b.WriteString(" " + clockTime(record) + "  ")
	b.WriteString(paint.Bold(Pad(Str(record, "op"), OpWidth)))
	b.WriteString(PaintOutcome(record, paint))
	b.WriteString(paint.Ref(Pad(outputNotes(record), 12)))
	b.WriteString(detail(record))
	return strings.TrimRight(b.String(), " ")
}

// detail is the command for an exec, the size of the text for a redact, and the
// managed file for an edit or a reseal, each of which would otherwise be a bare
// row naming only the op.
func detail(record map[string]any) string {
	if cmd := joinCmd(record); cmd != "" {
		return cmd
	}
	if size, ok := num(record, "input_bytes"); ok {
		return HumanBytes(int64(size)) + " in"
	}
	if file := Str(record, "file"); file != "" {
		return termsafe.Line(file)
	}
	if detail := Str(record, "error"); detail != "" {
		return termsafe.Line(detail)
	}
	return ""
}

// PaintOutcome pads before colouring: pad() counts escape bytes as width.
func PaintOutcome(record map[string]any, paint termui.Palette) string {
	const width = 16
	label, failed := Outcome(record)
	padded := Pad(label, width)
	switch {
	case label == "":
		return padded
	case failed:
		return paint.Bad(padded)
	}
	return paint.OK(padded)
}

// answerLabel is how a question's ending reads in the listing's column, or the
// code itself where this reader does not know it: a log written by a newer
// broker is read by whatever version is installed.
func answerLabel(code string) string {
	labels := map[string]string{
		escalation.CodeApproved:      "approved",
		escalation.CodeRejected:      "rejected",
		escalation.CodeExpired:       "timed out",
		escalation.CodeNotQuiescent:  "not quiescent",
		escalation.CodeRunEnded:      "run ended",
		escalation.CodeBrokerStopped: "broker stopped",
		escalation.CodeOtherCommand:  "other command",
		escalation.CodeUnnamed:       "unnamed",
		escalation.CodeUnownedRun:    "unowned run",
		escalation.CodeNoGrant:       "no grant",
	}
	if label, known := labels[code]; known {
		return label
	}
	return termsafe.Line(code)
}

// Outcome is how an exec ended, and whether that is a failure. A redact ran no
// command, so it has neither.
func Outcome(record map[string]any) (string, bool) {
	// The first half of a run's pair, which has no ending yet: said rather than
	// left blank, which would render a command still running as one that ran and
	// did nothing. "started" rather than "running", a log being read later: the
	// record is of a moment, and the missing second record is what says the
	// command never reported an ending.
	if Str(record, "op") == OpRunStarted {
		return "started", false
	}
	if timedOut, _ := boolean(record, "timed_out"); timedOut {
		return "timed out", true
	}
	// Killed because its caller went, which is the one ending nobody was told
	// about: the response went to a connection that had closed, so this row is
	// the whole of what is reported. Told apart from a timeout, and from the
	// bare "exit 137" it would otherwise read as, which says a signal and not
	// which one sent it.
	if abandoned, _ := boolean(record, "abandoned"); abandoned {
		return "caller gone", true
	}
	// An escalation ends in an answer rather than an exit code. Everything but a
	// yes is painted as a failure, not because refusing is wrong but because
	// something asked, which is what an operator is scanning for. Which no it
	// was comes from the code rather than the sentence beside it.
	if code := Str(record, "outcome_code"); code != "" {
		return answerLabel(code), code != escalation.CodeApproved
	}
	if approved, ok := boolean(record, "approved"); ok {
		if approved {
			return "approved", false
		}
		return "rejected", true
	}
	// The refusal's own code, which is the string the caller was answered with,
	// so an operator handed a log_id can confirm they are reading the refusal
	// that was cited.
	if refused := Str(record, "refused"); refused != "" {
		return refused, true
	}
	code, ok := num(record, "exit_code")
	if !ok {
		// No exit code and an error: this never became a finished command. Named
		// generically, the records shaped this way differing in how far they got,
		// and the error is on the detail view for all of them.
		if Str(record, "error") != "" {
			return "failed", true
		}
		return "", false
	}
	label := fmt.Sprintf("exit %d", int(code))
	// The run time, not the wall clock. A command blocked on its own escalation
	// sits inside sudo for the whole of it, so the wall clock says a script that
	// failed the instant it was approved took as long as the operator took to
	// answer. waited_sec is absent where nothing waited, and the two are then the
	// same number. The detail view carries the wait and the total.
	if seconds, ok := num(record, "duration_sec"); ok {
		waited, _ := num(record, "waited_sec")
		label += fmt.Sprintf(" %.2fs", max(seconds-waited, 0))
	}
	return label, code != 0
}
