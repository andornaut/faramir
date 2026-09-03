package auditview

// One record in full, field by field, which is what `logs --id` prints. Every
// value came from somewhere else, so each goes through internal/termui first.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/termsafe"
	"github.com/andornaut/faramir/internal/termui"
)

// redaction is one token and how often it stood in for its value.
type redaction struct {
	token string
	count int
}

// redactions is the record's counts, read once for both the listing's sum and
// the detail view's per-token line.
func redactions(record map[string]any) []redaction {
	entries, ok := record["redactions"].([]any)
	if !ok {
		return nil
	}
	out := make([]redaction, 0, len(entries))
	for _, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		count, _ := num(fields, "count")
		out = append(out, redaction{token: str(fields, "token"), count: int(count)})
	}
	return out
}

// outputNotes is what happened to the output, in the column between the outcome
// and the command: how much was replaced by a token, and whether what is
// recorded is the whole of what the command wrote. `run` tells the caller both
// of the last two on stderr, so the log says them too, or an operator reading a
// record back is shown an excerpt of a lossy rendering as though it were the
// output. Longer than the column on the rare record carrying all three, which
// shifts that row rather than hiding what it says.
func outputNotes(record map[string]any) string {
	var notes []string
	if total := redactionTotal(record); total != "" {
		notes = append(notes, total)
	}
	if truncated, _ := boolean(record, "output_truncated"); truncated {
		notes = append(notes, "truncated")
	}
	if invalid, ok := num(record, "invalid_bytes"); ok && invalid > 0 {
		notes = append(notes, "non-text")
	}
	return strings.Join(notes, ", ")
}

// redactionTotal is how many values this record stood in for, summed across
// tokens: a credential was used, without saying which.
func redactionTotal(record map[string]any) string {
	total := 0
	for _, entry := range redactions(record) {
		total += entry.count
	}
	if total == 0 {
		return ""
	}
	return fmt.Sprintf("%d redacted", total)
}

// printField is one labelled line of the detail view, skipped when there is
// nothing under the label.
func printField(paint termui.Palette, label, value string) {
	const labelWidth = 10
	if value == "" {
		return
	}
	fmt.Printf("  %s %s\n", paint.Key(termui.Pad(label, labelWidth)), value)
}

// PrintRecord is the whole of one record, output included.
func PrintRecord(record map[string]any, paint termui.Palette) {
	// The summary line leads with the id, so it is not repeated as a field
	// below.
	fmt.Println(summarise(record, paint))
	// Above the fields it qualifies rather than under them: a reader has to know
	// the record was cut before believing a short argv or a truncated ref list.
	if reduced, _ := boolean(record, "record_reduced"); reduced {
		printField(paint, "reduced", paint.Dim(
			"fields were cut to fit the record cap"))
	}
	printField(paint, "caller", describePeer(record))
	// The labels are not all the field names. argv0_path reads as `program`, the
	// word the escalation question uses for what root or the executor actually
	// ran, and sits under the cwd a relative argv[0] resolved against. outcome is
	// the escalation's own reason, and run_log_id is the command's record, so an
	// escalation reads in both directions.
	//
	// Rendered, not printed: all of these carry text chosen by the account this
	// log exists to hold to account.
	for _, row := range []struct{ field, label string }{
		{"cwd", "cwd"}, {"argv0_path", "program"}, {"error", "error"},
		{"outcome", "outcome"}, {"reason", "reason"}, {"run_log_id", "run_log_id"},
	} {
		if value := str(record, row.field); value != "" {
			printField(paint, row.label, termsafe.Line(value))
		}
	}
	// Only where the command waited: on every other record the run time in the
	// summary line above is the whole of it, and two more rows saying so would
	// be noise on every record in the log.
	if waited, ok := num(record, "waited_sec"); ok && waited > 0 {
		total, _ := num(record, "duration_sec")
		printField(paint, "waited", fmt.Sprintf(
			"%.2fs for approval, of %.2fs in total",
			waited, total))
	}
	printField(paint, "refs", paint.Ref(envRefs(record)))
	// A reseal's recipients: who could read that file before, and who can now.
	// Public keys, so printing them discloses nothing the ciphertext does not
	// already carry.
	for _, field := range []string{"from", "to"} {
		printField(paint, field, paint.Ref(strings.Join(list(record, field), ", ")))
	}
	printField(paint, "redacted", paint.Ref(redactionCounts(record)))
	// What the output is not. Each only where it happened: on an ordinary record
	// the output is what the command wrote and a row saying so is noise.
	if truncated, _ := boolean(record, "output_truncated"); truncated {
		dropped, _ := num(record, "output_dropped")
		kept, _ := record["output"].(string)
		printField(paint, "output cut", fmt.Sprintf(
			"%d byte(s) kept, %d dropped: this is an excerpt, not the whole of it",
			len(kept), int64(dropped)))
	}
	if invalid, ok := num(record, "invalid_bytes"); ok && invalid > 0 {
		printField(paint, "non-text", fmt.Sprintf(
			"%d byte(s) were not valid UTF-8 and are recorded as U+FFFD", int64(invalid)))
	}
	output, _ := record["output"].(string)
	if output == "" {
		return
	}
	fmt.Printf("  %s\n", paint.Key("output"))
	// One line at a time and escaped, never quoted or truncated: this is the text
	// the operator came to read. redact.Feed already took the colour and the CSI
	// on the way in, so what is left to escape is a bare "\r" or a stray ESC.
	for line := range strings.SplitSeq(strings.TrimRight(output, "\n"), "\n") {
		fmt.Printf("    %s\n", paint.Token(termsafe.Line(line)))
	}
	if truncated, _ := boolean(record, "output_truncated"); truncated {
		fmt.Printf("    %s\n", paint.Dim("[truncated at the record cap]"))
	}
}

// envRefs is what the command asked to be injected, as NAME=ref: which variable
// carried which ref, which is what an operator checks an injection against.
// Neither half is a value. Sorted by variable name, so the same command reads
// the same way every time.
func envRefs(record map[string]any) string {
	fields, ok := record["env_refs"].(map[string]any)
	if !ok {
		return ""
	}
	pairs := make([]string, 0, len(fields))
	for name, ref := range fields {
		if text, ok := ref.(string); ok {
			pairs = append(pairs, name+"="+text)
		}
	}
	sort.Strings(pairs)
	// Rendered like every other field taken from a record: a log written by
	// something else is one of the things this reader is for.
	return termsafe.Line(strings.Join(pairs, ", "))
}

// redactionCounts is per token, for the detail view; the listing sums them.
func redactionCounts(record map[string]any) string {
	counts := redactions(record)
	out := make([]string, 0, len(counts))
	for _, entry := range counts {
		out = append(out, fmt.Sprintf("%s×%d", entry.token, entry.count))
	}
	return strings.Join(out, ", ")
}

// joinCmd is the recorded argv as one line, rendered for a terminal: it is the
// coding agent's own text, printed to the operator's.
func joinCmd(record map[string]any) string {
	args := list(record, "cmd")
	for i, arg := range args {
		args[i] = termsafe.Arg(arg)
	}
	return strings.Join(args, " ")
}
