// Package auditview reads the broker's audit log and renders a record for a
// person.
//
// Reading it is not just decoding JSON. The log is appended to while it is being
// read and rotated out from under a reader, so following it means noticing that
// the file it holds open is no longer the file at the path; and a record may be
// truncated mid-write, so a line that does not parse is counted rather than
// fatal.
//
// Rendering it is not just printing fields. Every value in a record came from
// somewhere else -- a command line, a peer's name, a path -- and a terminal
// obeys what it is sent, so what reaches one goes through internal/termui
// first. The «SECRET:ref» markers are the exception worth painting: they say
// where a credential was used without being one.
package auditview

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termsafe"
	"github.com/andornaut/faramir/internal/termui"
)

// Printer is the listing's rows and the date header above the first row of
// each day. The day it last printed is state, so a watcher left running prints
// a new header when the day turns under it.
type Printer struct {
	Paint termui.Palette
	day   string
}

func (p *Printer) Row(record map[string]any) {
	if at := StartedAt(record); !at.IsZero() && at.Format(dateLayout) != p.day {
		p.day = at.Format(dateLayout)
		fmt.Println(p.Paint.Dim(p.day))
	}
	fmt.Println(Summarise(record, p.Paint))
}

// scanAuditLog calls visit with each line of the log, in order, and stops early
// when visit returns false. It holds one line at a time, so what it costs is
// the largest record rather than the file; the record cap bounds a line at the
// writer, which is the only place that can bound it.
//
// visit is handed the line with its newline where it had one. A line with none
// is the last, caught midway through an append.
func scanAuditLog(path string, visit func(line []byte) bool) error {
	fh, err := openAuditLog(path)
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()

	reader := bufio.NewReaderSize(fh, 64*1024)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 && !visit(line) {
			return nil
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", path, readErr)
		}
	}
}

// openAuditLog is the log, with the missing-file case named: "no such file"
// alone reads as a path typo rather than as a host where nothing has been
// brokered.
func openAuditLog(path string) (*os.File, error) {
	fh, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		return nil, missingLog(path)
	}
	return fh, err
}

// missingLog is that message on its own, for a caller that opens the log itself
// because it has to tell "not there" from every other reason a file will not
// open.
func missingLog(path string) error {
	return fmt.Errorf("no audit log at %s. Nothing has been brokered on "+
		"this host, or [audit] log_path names somewhere else", path)
}

// ParseLine is one line as a record, and whether losing it means a record was
// lost. The one unparseable line that is not evidence of a loss is the last,
// with no newline on the end: nothing finished writing it.
//
// A nil record counts as lost too: "null" unmarshals into a map without error,
// leaving it nil, so testing the error alone would drop that line silently.
func ParseLine(line []byte) (record map[string]any, lost bool) {
	if err := json.Unmarshal(line, &record); err != nil || record == nil {
		return nil, bytes.HasSuffix(line, []byte("\n"))
	}
	return record, false
}

// RingCapMax bounds what the ring is sized to up front: --count accepts any
// int, so sizing to it would cost a slice header times that number before a
// line has been read. The ring grows to what the log actually holds.
const RingCapMax = 1024

func RingCap(count int) int { return min(count, RingCapMax) }

// Ring keeps the last count lines it was given. A count of zero or less
// keeps nothing, which is what --count asked for.
type Ring struct {
	count  int
	lines  [][]byte
	next   int
	filled bool
}

func NewRing(count int) *Ring {
	return &Ring{count: count, lines: make([][]byte, 0, max(RingCap(count), 0))}
}

func (r *Ring) Add(line []byte) {
	if r.count <= 0 {
		return
	}
	// Copied: the reader owns its buffer and reuses it on the next line.
	kept := append([]byte(nil), line...)
	if !r.filled && len(r.lines) < r.count {
		r.lines = append(r.lines, kept)
		r.filled = len(r.lines) == r.count
		return
	}
	r.lines[r.next] = kept
	if r.next++; r.next == r.count {
		r.next = 0
	}
}

// Ordered is what it holds, oldest first.
func (r *Ring) Ordered() [][]byte {
	if !r.filled {
		return r.lines
	}
	return append(append([][]byte{}, r.lines[r.next:]...), r.lines[:r.next]...)
}

// ParseLines is the records in a batch of lines, and how many of them were lost.
func ParseLines(lines [][]byte) ([]map[string]any, int) {
	var records []map[string]any
	skipped := 0
	for _, line := range lines {
		record, lost := ParseLine(line)
		switch {
		case record != nil:
			records = append(records, record)
		case lost:
			skipped++
		}
	}
	return records, skipped
}

// Tail is the last count records, parsed. The last count lines are kept
// as bytes and parsed at the end, so what this holds is bounded by what was
// asked for rather than by how long the log is.
//
// A count of zero or less asks for nothing and gets nothing. The log is still
// opened, so a host with no log at all says so rather than reporting an empty
// listing.
func Tail(path string, count int) ([]map[string]any, int, error) {
	if count <= 0 {
		fh, err := openAuditLog(path)
		if err != nil {
			return nil, 0, err
		}
		_ = fh.Close()
		return nil, 0, nil
	}
	ring := NewRing(count)
	if err := scanAuditLog(path, func(line []byte) bool {
		ring.Add(line)
		return true
	}); err != nil {
		return nil, 0, err
	}
	records, skipped := ParseLines(ring.Ordered())
	return records, skipped, nil
}

// Follower reads a log that is still being written. It holds the reader open
// between passes, so a quiet host costs a stat per poll rather than a re-read.
//
// Complete lines only: a record still being appended is held until its newline
// arrives, where scanAuditLog hands the last line over whether or not it ends.
//
// A Follower with no file is a state rather than a failure: the path holds none
// between logrotate's rename and the next record, and none at all on a host
// where nothing has been brokered yet. Detached, it reads nothing and reports
// no rotation until a file is there.
type Follower struct {
	path    string
	fh      *os.File
	reader  *bufio.Reader
	info    os.FileInfo
	pending []byte
	offset  int64
}

// OpenFollower is a follower on path, attached if there is a file there and
// detached if there is not.
func OpenFollower(path string) (*Follower, error) {
	f := &Follower{path: path}
	if err := f.open(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return f, nil
}

// open returns the raw error, not openAuditLog's sentence: the caller has to
// tell a path with no file at it, which is a pass to wait, from one that cannot
// be opened at all. Every field is cleared first, so a failure leaves a
// detached follower rather than one holding a closed reader.
func (f *Follower) open() error {
	f.fh, f.reader, f.info = nil, nil, nil
	f.pending, f.offset = nil, 0
	fh, err := os.Open(f.path)
	if err != nil {
		return err
	}
	info, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return fmt.Errorf("%s: %w", f.path, err)
	}
	f.fh, f.info = fh, info
	f.reader = bufio.NewReaderSize(fh, 64*1024)
	return nil
}

// Following is whether there is a file open to read from.
func (f *Follower) Following() bool { return f.reader != nil }

// Reopen is the file the path names now, read from its start. The half-written
// line held from the file before is dropped with it: it belongs to a record in
// the rotated file.
func (f *Follower) Reopen() error {
	f.Close()
	return f.open()
}

func (f *Follower) Close() {
	if f.fh != nil {
		_ = f.fh.Close()
	}
}

// Drain calls visit with each line completed since the last pass, and returns
// when it reaches the end of what has been written. Blank lines are skipped,
// as in scanAuditLog. Nothing to read while detached, which is not an error:
// rotated() is what says a file has appeared.
func (f *Follower) Drain(visit func(line []byte)) error {
	if !f.Following() {
		return nil
	}
	for {
		chunk, err := f.reader.ReadBytes('\n')
		f.offset += int64(len(chunk))
		f.pending = append(f.pending, chunk...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", f.path, err)
		}
		line := f.pending
		f.pending = nil
		if len(bytes.TrimSpace(line)) > 0 {
			visit(line)
		}
	}
}

// Rotated is whether the file being read is no longer the log: logrotate
// renamed it and the path now names a different file, or something emptied it
// in place and it is shorter than what has already been read.
//
// A path with nothing at it is neither: that is the gap between logrotate's
// rename and the next record. A file at a path a detached follower holds
// counts, os.SameFile being false against its nil info, which is what attaches
// the follower to the first log a host ever writes.
func (f *Follower) Rotated() (bool, error) {
	info, err := os.Stat(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", f.path, err)
	}
	return !os.SameFile(info, f.info) || info.Size() < f.offset, nil
}

// Find is the last record whose id matches, or nil. It parses one line
// at a time and keeps only the match, so a lookup costs the same on a log of
// any length.
//
// The last rather than the first, because a run writes a pair sharing one
// log_id: an ending where there is one, and the start where the command is
// still running. A log_id is distinct by construction (see audit.NewLogID), so
// the pair is the only reason there is ever more than one.
func Find(path, id string) (map[string]any, int, error) {
	var found map[string]any
	skipped := 0
	err := scanAuditLog(path, func(line []byte) bool {
		record, lost := ParseLine(line)
		if lost {
			skipped++
		}
		if record == nil || !MatchesID(record, id) {
			return true
		}
		found = record
		// Stopped at the ending, which is the last of the pair: reading on would
		// scan the whole file for a record already in hand. A start half is not
		// the end of the pair, so that one reads on.
		return Str(record, "op") == OpRunStarted
	})
	return found, skipped, err
}

// ReportSkipped says what was not shown: a listing that looks complete when a
// record is missing from it answers the question wrongly. internal/audit takes
// back a short write, so a line that will not parse was written by something
// else or damaged after the fact.
func ReportSkipped(path string, skipped int) {
	if skipped == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "faramir logs: %s: %d line(s) do not parse and are not shown. "+
		"The broker writes one record per line and takes back a write that lands "+
		"short, so a line like this was written by something else or damaged "+
		"afterwards\n", path, skipped)
}

// EmptyReason is why the listing is empty. A count that asked for nothing and
// a log that holds nothing are different answers. An absent log is neither,
// and tailRecords reports it by opening the file whatever the count was.
func EmptyReason(path string, count int) string {
	if count <= 0 {
		return fmt.Sprintf("--count %d asks for no records. Pass a positive count to "+
			"list some, or a log-id to look one up", count)
	}
	return path + " holds no records to show"
}

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
		out = append(out, redaction{token: Str(fields, "token"), count: int(count)})
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
	fmt.Printf("  %s %s\n", paint.Key(Pad(label, labelWidth)), value)
}

// PrintRecord is the whole of one record, output included.
func PrintRecord(record map[string]any, paint termui.Palette) {
	// The summary line leads with the id, so it is not repeated as a field
	// below.
	fmt.Println(Summarise(record, paint))
	// Above the fields it qualifies rather than under them: a reader has to know
	// the record was cut before believing a short argv or a truncated ref list.
	if reduced, _ := boolean(record, "record_reduced"); reduced {
		printField(paint, "reduced", paint.Dim(
			"fields were cut to fit the record cap"))
	}
	printField(paint, "caller", DescribePeer(record))
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
		if value := Str(record, row.field); value != "" {
			printField(paint, row.label, termsafe.Line(value))
		}
	}
	// Only where the command waited: on every other record the run time in the
	// summary line above is the whole of it, and two more rows saying so would
	// be noise on every record in the log.
	if waited, ok := num(record, "waited_sec"); ok && waited > 0 {
		total, _ := num(record, "duration_sec")
		printField(paint, "waited", fmt.Sprintf(
			"%.2fs to be approved, of %.2fs between registering and exiting",
			waited, total))
	}
	printField(paint, "refs", paint.Ref(envRefs(record)))
	// A reseal's recipients: who could read that file before, and who can now.
	// Public keys, so printing them discloses nothing the ciphertext does not
	// already carry.
	for _, field := range []string{"from", "to"} {
		printField(paint, field, paint.Ref(strings.Join(list(record, field), ", ")))
	}
	printField(paint, "redacted", paint.Ref(RedactionCounts(record)))
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

// RedactionCounts is per token, for the detail view; the listing sums them.
func RedactionCounts(record map[string]any) string {
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

// dateLayout is the day heading a run of records sits under. The zone is in
// the header because the times below are local and the log_id beside them is
// UTC.
const dateLayout = "2006-01-02 MST"

// StampLayout is one moment in full, for a line that stands on its own rather
// than under a day heading: DateLayout's day and zone with the time the log
// prints against it. The approval prompt is the one place that needs it, a
// question being read without the surrounding day the log has.
const StampLayout = "2006-01-02 15:04:05 MST"

// StartedAt is when the record's subject happened: started_at where the record
// has one, which is the child's fork rather than the moment the line was
// written, and otherwise the `at` every other record carries.
func StartedAt(record map[string]any) time.Time {
	for _, field := range []string{"started_at", "at"} {
		if seconds, ok := num(record, field); ok {
			return time.Unix(int64(seconds), 0)
		}
	}
	return time.Time{}
}

// clockTime is local, the log being read against what somebody remembers doing.
func clockTime(record map[string]any) string {
	at := StartedAt(record)
	if at.IsZero() {
		return "        "
	}
	return at.Format("15:04:05")
}

// MatchesID compares the log_id as it is printed, so what is on screen pastes
// back.
func MatchesID(record map[string]any, want string) bool {
	return Str(record, "log_id") == want
}

// DescribePeer renders the caller from pid, uid and gid, resolving the uid to a
// name where the account still exists.
func DescribePeer(record map[string]any) string {
	fields, ok := record["peer"].(map[string]any)
	if !ok {
		return ""
	}
	uid, _ := num(fields, "uid")
	pid, _ := num(fields, "pid")
	who := fmt.Sprintf("uid %d", int(uid))
	if account, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		who = fmt.Sprintf("%s (uid %d)", account.Username, int(uid))
	}
	return fmt.Sprintf("%s, pid %d", who, int(pid))
}

// HumanBytes keeps a size to three significant figures; this column is for
// judging scale.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, exponent := float64(n)/unit, 0
	for value >= unit && exponent < 3 {
		value /= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", value, "KMGT"[exponent])
}

func Str(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

// num is a recorded number and whether the field was there. encoding/json
// returns every number as a float64, and the callers here have to tell an
// absent exit code from one of zero.
func num(record map[string]any, key string) (float64, bool) {
	value, ok := record[key].(float64)
	return value, ok
}

// boolean is a recorded flag and whether the field was there. Not `flag`,
// which is a standard library package this file's callers use.
func boolean(record map[string]any, key string) (bool, bool) {
	value, ok := record[key].(bool)
	return value, ok
}

func list(record map[string]any, key string) []string {
	entries, ok := record[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if text, ok := entry.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// Pad is one column of the listing, widened to width. A value already that
// wide still gets a space, or it runs into the column after it. Counted in
// runes, not bytes: the ellipsis a cut record's fields end with is three bytes
// and one column.
func Pad(text string, width int) string {
	spent := utf8.RuneCountInString(text)
	if spent >= width {
		return text + " "
	}
	return text + strings.Repeat(" ", width-spent)
}
