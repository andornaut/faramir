package main

// faramir logs: read the audit log without having to remember where it is.
//
// Root only, and not brokered: the log is 0600 faramir-broker, and serving it
// over the broker socket would hand it to the group the agent runs as. It
// holds no secret value -- output was recorded after redaction, refs are names,
// nothing is substituted into argv -- so this prints what it finds.
//
// [audit] log_path says which file, and there is no flag naming another: a
// reader pointed at a path by hand is a typo away from reporting a host as
// quiet. FARAMIR_CONFIG moves it. Rotated files are not read;
// name one to zless. --watch is the one place rotation is followed: a watcher
// left running across a logrotate run reopens the path and carries on.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termsafe"
)

// How many records a bare `faramir logs` lists. A screenful; a specific record
// is asked for by log_id.
const defaultLogCount = 20

// watchPoll is how often a watcher looks for what has been appended: short
// enough that a row follows the command that wrote it, long enough that a
// terminal left open overnight is not a stat per hundredth of a second.
const watchPoll = 500 * time.Millisecond

type logsFlags struct {
	count  int
	asJSON bool
	watch  bool
	when   string
}

func newLogsCmd() *cobra.Command {
	var f logsFlags
	c := &cobra.Command{
		Use:     "logs [options] [LOG-ID]",
		Short:   "Show the audit log: what ran, against which refs, and how it ended",
		GroupID: groupProvisioning,
		Args:    atMostOneArg("log-id"),
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runLogs(f, args)) },
	}
	c.Flags().IntVarP(&f.count, "count", "n", defaultLogCount, "how many recent records to list")
	c.Flags().BoolVar(&f.asJSON, "json", false, "print the records as JSON")
	c.Flags().BoolVar(&f.watch, "watch", false, "keep printing records as they are appended")
	addColorFlag(c, &f.when)
	return c
}

func runLogs(f logsFlags, args []string) int {
	paint, err := newPalette(f.when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 2
	}

	// A log-id names a command already recorded, so there is nothing to watch for.
	// Blocked before the root check, so the answer is the same whoever typed it.
	if f.watch && firstArg(args) != "" {
		fmt.Fprintln(os.Stderr, "faramir logs: --watch prints records as they arrive, "+
			"so it takes no log-id. Drop one or the other")
		return 2
	}

	// Blocked rather than attempted: otherwise a bare permission error on a path
	// the caller did not name.
	if !requireRoot("logs", "the audit log is readable only by the broker and by root") {
		return 1
	}

	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	path := cfg.Audit.LogPath

	if id := firstArg(args); id != "" {
		record, skipped, err := findRecord(path, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		reportSkipped(path, skipped)
		if record == nil {
			fmt.Fprintf(os.Stderr, "faramir logs: no record %s in %s. Rotated files are not "+
				"searched; a record older than the live log is in %s.1.gz and its siblings\n",
				id, path, filepath.Base(path))
			return 1
		}
		if f.asJSON {
			return printJSON("logs", record)
		}
		printRecord(record, paint)
		return 0
	}

	if f.watch {
		return runWatch(path, f, paint)
	}

	records, skipped, err := tailRecords(path, f.count)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	reportSkipped(path, skipped)
	if f.asJSON {
		// An empty listing is a JSON empty array, not null: a caller parsing stdout
		// gets a value either way.
		if records == nil {
			records = []map[string]any{}
		}
		return printJSON("logs", records)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, emptyReason(path, f.count))
		return 0
	}
	printer := logPrinter{paint: paint}
	for _, record := range records {
		printer.row(record)
	}
	return 0
}

// logPrinter is the listing's rows and the date header above the first row of
// each day. The day it last printed is state, so a watcher left running prints
// a new header when the day turns under it.
type logPrinter struct {
	paint palette
	day   string
}

func (p *logPrinter) row(record map[string]any) {
	if at := startedAt(record); !at.IsZero() && at.Format(dateLayout) != p.day {
		p.day = at.Format(dateLayout)
		fmt.Println(p.paint.dim(p.day))
	}
	fmt.Println(summarise(record, p.paint))
}

// runWatch prints the last count records and then the records appended after
// them, until it is interrupted. It returns only on an error it cannot read
// past. One reader throughout, positioned at the end of the file the backlog
// was read from, so a record written while the backlog is printing is shown
// once rather than twice or not at all.
func runWatch(path string, f logsFlags, paint palette) int {
	follow, err := openFollower(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	defer follow.close()

	printer := logPrinter{paint: paint}
	skipped := 0
	// A record on the way past. --json prints one value per record rather than
	// the listing's array: there is no last record to close an array after.
	emit := func(line []byte) {
		record, lost := parseLine(line)
		switch {
		case record == nil:
			if lost {
				skipped++
			}
		case f.asJSON:
			_ = printJSON("logs", record)
		default:
			printer.row(record)
		}
	}

	// The backlog, read through the same reader: kept as bytes and parsed at the
	// end, as the listing does it.
	backlog := newLineRing(f.count)
	if err := follow.drain(backlog.add); err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	records, lost := parseLines(backlog.ordered())
	reportSkipped(path, lost)
	// Said only where the count asked for records: `--watch -n 0` asked for the
	// arriving ones alone. A log that is not there yet is its own answer, this
	// waiting for it rather than reporting it as empty.
	switch {
	case !follow.following():
		fmt.Fprintf(os.Stderr, "no audit log at %s yet: nothing has been brokered "+
			"on this host, and the first record creates it\n", path)
	case len(records) == 0 && f.count > 0:
		fmt.Fprintln(os.Stderr, emptyReason(path, f.count))
	}
	for _, record := range records {
		if f.asJSON {
			_ = printJSON("logs", record)
			continue
		}
		printer.row(record)
	}
	fmt.Fprintf(os.Stderr, "watching %s for new records. Ctrl-c to stop.\n", path)

	for {
		if err := follow.drain(emit); err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		// Per pass rather than per line: a run of lines that will not parse is one
		// report.
		reportSkipped(path, skipped)
		skipped = 0

		rotated, err := follow.rotated()
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		if rotated {
			switch err := follow.reopen(); {
			case err == nil:
				// Straight round again rather than waiting a poll: the file at the path
				// is a new one, read from its start.
				continue
			case !os.IsNotExist(err):
				fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
				return 1
			}
			// The file went between the stat and the open, so the follower is
			// detached and reads nothing until one is back at the path.
		}
		time.Sleep(watchPoll)
	}
}

// printJSON writes a record, a list of them or a report to stdout as indented
// JSON: the machine-readable form of what the text listing shows. One function
// for every command that takes --json, so a marshal that fails is an exit code
// in each rather than an empty stdout in some of them: under --json the
// document is the whole answer, and exiting 0 having printed nothing reads to a
// configuration manager as a host that needed no work.
//
// label names the subcommand for the error, the caller having it and this not.
func printJSON(label string, v any) int {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	fmt.Println(string(body))
	return 0
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

// parseLine is one line as a record, and whether losing it means a record was
// lost. The one unparseable line that is not evidence of a loss is the last,
// with no newline on the end: nothing finished writing it.
//
// A nil record counts as lost too: "null" unmarshals into a map without error,
// leaving it nil, so testing the error alone would drop that line silently.
func parseLine(line []byte) (record map[string]any, lost bool) {
	if err := json.Unmarshal(line, &record); err != nil || record == nil {
		return nil, bytes.HasSuffix(line, []byte("\n"))
	}
	return record, false
}

// ringCapMax bounds what the ring is sized to up front: --count accepts any
// int, so sizing to it would cost a slice header times that number before a
// line has been read. The ring grows to what the log actually holds.
const ringCapMax = 1024

func ringCap(count int) int { return min(count, ringCapMax) }

// lineRing keeps the last count lines it was given. A count of zero or less
// keeps nothing, which is what --count asked for.
type lineRing struct {
	count  int
	lines  [][]byte
	next   int
	filled bool
}

func newLineRing(count int) *lineRing {
	return &lineRing{count: count, lines: make([][]byte, 0, max(ringCap(count), 0))}
}

func (r *lineRing) add(line []byte) {
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

// ordered is what it holds, oldest first.
func (r *lineRing) ordered() [][]byte {
	if !r.filled {
		return r.lines
	}
	return append(append([][]byte{}, r.lines[r.next:]...), r.lines[:r.next]...)
}

// parseLines is the records in a batch of lines, and how many of them were lost.
func parseLines(lines [][]byte) ([]map[string]any, int) {
	var records []map[string]any
	skipped := 0
	for _, line := range lines {
		record, lost := parseLine(line)
		switch {
		case record != nil:
			records = append(records, record)
		case lost:
			skipped++
		}
	}
	return records, skipped
}

// tailRecords is the last count records, parsed. The last count lines are kept
// as bytes and parsed at the end, so what this holds is bounded by what was
// asked for rather than by how long the log is.
//
// A count of zero or less asks for nothing and gets nothing. The log is still
// opened, so a host with no log at all says so rather than reporting an empty
// listing.
func tailRecords(path string, count int) ([]map[string]any, int, error) {
	if count <= 0 {
		fh, err := openAuditLog(path)
		if err != nil {
			return nil, 0, err
		}
		_ = fh.Close()
		return nil, 0, nil
	}
	ring := newLineRing(count)
	if err := scanAuditLog(path, func(line []byte) bool {
		ring.add(line)
		return true
	}); err != nil {
		return nil, 0, err
	}
	records, skipped := parseLines(ring.ordered())
	return records, skipped, nil
}

// follower reads a log that is still being written. It holds the reader open
// between passes, so a quiet host costs a stat per poll rather than a re-read.
//
// Complete lines only: a record still being appended is held until its newline
// arrives, where scanAuditLog hands the last line over whether or not it ends.
//
// A follower with no file is a state rather than a failure: the path holds none
// between logrotate's rename and the next record, and none at all on a host
// where nothing has been brokered yet. Detached, it reads nothing and reports
// no rotation until a file is there.
type follower struct {
	path    string
	fh      *os.File
	reader  *bufio.Reader
	info    os.FileInfo
	pending []byte
	offset  int64
}

// openFollower is a follower on path, attached if there is a file there and
// detached if there is not.
func openFollower(path string) (*follower, error) {
	f := &follower{path: path}
	if err := f.open(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return f, nil
}

// open returns the raw error, not openAuditLog's sentence: the caller has to
// tell a path with no file at it, which is a pass to wait, from one that cannot
// be opened at all. Every field is cleared first, so a failure leaves a
// detached follower rather than one holding a closed reader.
func (f *follower) open() error {
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

// following is whether there is a file open to read from.
func (f *follower) following() bool { return f.reader != nil }

// reopen is the file the path names now, read from its start. The half-written
// line held from the file before is dropped with it: it belongs to a record in
// the rotated file.
func (f *follower) reopen() error {
	f.close()
	return f.open()
}

func (f *follower) close() {
	if f.fh != nil {
		_ = f.fh.Close()
	}
}

// drain calls visit with each line completed since the last pass, and returns
// when it reaches the end of what has been written. Blank lines are skipped,
// as in scanAuditLog. Nothing to read while detached, which is not an error:
// rotated() is what says a file has appeared.
func (f *follower) drain(visit func(line []byte)) error {
	if !f.following() {
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

// rotated is whether the file being read is no longer the log: logrotate
// renamed it and the path now names a different file, or something emptied it
// in place and it is shorter than what has already been read.
//
// A path with nothing at it is neither: that is the gap between logrotate's
// rename and the next record. A file at a path a detached follower holds
// counts, os.SameFile being false against its nil info, which is what attaches
// the follower to the first log a host ever writes.
func (f *follower) rotated() (bool, error) {
	info, err := os.Stat(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", f.path, err)
	}
	return !os.SameFile(info, f.info) || info.Size() < f.offset, nil
}

// findRecord is the last record whose id matches, or nil. It parses one line
// at a time and keeps only the match, so a lookup costs the same on a log of
// any length.
//
// The last rather than the first, because a run writes a pair sharing one
// log_id: an ending where there is one, and the start where the command is
// still running. A log_id is distinct by construction (see audit.NewLogID), so
// the pair is the only reason there is ever more than one.
func findRecord(path, id string) (map[string]any, int, error) {
	var found map[string]any
	skipped := 0
	err := scanAuditLog(path, func(line []byte) bool {
		record, lost := parseLine(line)
		if lost {
			skipped++
		}
		if record == nil || !matchesID(record, id) {
			return true
		}
		found = record
		// Stopped at the ending, which is the last of the pair: reading on would
		// scan the whole file for a record already in hand. A start half is not
		// the end of the pair, so that one reads on.
		return str(record, "op") == opRunStarted
	})
	return found, skipped, err
}

// reportSkipped says what was not shown: a listing that looks complete when a
// record is missing from it answers the question wrongly. internal/audit takes
// back a short write, so a line that will not parse was written by something
// else or damaged after the fact.
func reportSkipped(path string, skipped int) {
	if skipped == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "faramir logs: %s: %d line(s) do not parse and are not shown. "+
		"The broker writes one record per line and takes back a write that lands "+
		"short, so a line like this was written by something else or damaged "+
		"afterwards\n", path, skipped)
}

// emptyReason is why the listing is empty. A count that asked for nothing and
// a log that holds nothing are different answers. An absent log is neither,
// and tailRecords reports it by opening the file whatever the count was.
func emptyReason(path string, count int) string {
	if count <= 0 {
		return fmt.Sprintf("--count %d asks for no records. Pass a positive count to "+
			"list some, or a log-id to look one up", count)
	}
	return path + " holds no records to show"
}

// logIDWidth is what audit.NewLogID mints plus the separating space, sized past
// the id rather than to it; see opWidth.
const logIDWidth = 15

// opWidth is the longest op recorded, `run_started` at eleven, plus the
// separating space. Sized past the longest rather than to it: pad appends a
// space to anything already at the width, so a column exactly as wide as its
// longest value puts every following column of that row somewhere else.
const opWidth = 12

// opRunStarted is the first half of the pair a run writes, and the one record
// with no ending in it. Named here as well as at the broker that writes it:
// this reader is pointed at a file, not linked to the daemon.
const opRunStarted = "run_started"

// opEdit and opReseal are what the edit and reseal commands record.
const (
	opEdit   = "edit"
	opReseal = "reseal"
)

// summarise is one record on one line: when, what, how it ended, how many
// values it touched, and the id to ask for the rest. The id is printed whole,
// which is what a lookup takes.
func summarise(record map[string]any, paint palette) string {
	var b strings.Builder
	b.WriteString(paint.dim(pad(str(record, "log_id"), logIDWidth)))
	b.WriteString(" " + clockTime(record) + "  ")
	b.WriteString(paint.bold(pad(str(record, "op"), opWidth)))
	b.WriteString(paintOutcome(record, paint))
	b.WriteString(paint.ref(pad(outputNotes(record), 12)))
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
		return humanBytes(int64(size)) + " in"
	}
	if file := str(record, "file"); file != "" {
		return termsafe.Line(file)
	}
	if detail := str(record, "error"); detail != "" {
		return termsafe.Line(detail)
	}
	return ""
}

// paintOutcome pads before colouring: pad() counts escape bytes as width.
func paintOutcome(record map[string]any, paint palette) string {
	const width = 16
	label, failed := outcome(record)
	padded := pad(label, width)
	switch {
	case label == "":
		return padded
	case failed:
		return paint.bad(padded)
	}
	return paint.ok(padded)
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

// outcome is how an exec ended, and whether that is a failure. A redact ran no
// command, so it has neither.
func outcome(record map[string]any) (string, bool) {
	// The first half of a run's pair, which has no ending yet: said rather than
	// left blank, which would render a command still running as one that ran and
	// did nothing. "started" rather than "running", a log being read later: the
	// record is of a moment, and the missing second record is what says the
	// command never reported an ending.
	if str(record, "op") == opRunStarted {
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
	if code := str(record, "outcome_code"); code != "" {
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
	if refused := str(record, "refused"); refused != "" {
		return refused, true
	}
	code, ok := num(record, "exit_code")
	if !ok {
		// No exit code and an error: this never became a finished command. Named
		// generically, the records shaped this way differing in how far they got,
		// and the error is on the detail view for all of them.
		if str(record, "error") != "" {
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
		out = append(out, redaction{token: str(fields, "token"), count: int(count)})
	}
	return out
}

// redactionTotal is how many values this record stood in for, summed across
// tokens: a credential was used, without saying which.
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
func printField(paint palette, label, value string) {
	const labelWidth = 10
	if value == "" {
		return
	}
	fmt.Printf("  %s %s\n", paint.key(pad(label, labelWidth)), value)
}

// printRecord is the whole of one record, output included.
func printRecord(record map[string]any, paint palette) {
	// The summary line leads with the id, so it is not repeated as a field
	// below.
	fmt.Println(summarise(record, paint))
	// Above the fields it qualifies rather than under them: a reader has to know
	// the record was cut before believing a short argv or a truncated ref list.
	if reduced, _ := boolean(record, "record_reduced"); reduced {
		printField(paint, "reduced", paint.dim(
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
			"%.2fs to be approved, of %.2fs between registering and exiting",
			waited, total))
	}
	printField(paint, "refs", paint.ref(envRefs(record)))
	// A reseal's recipients: who could read that file before, and who can now.
	// Public keys, so printing them discloses nothing the ciphertext does not
	// already carry.
	for _, field := range []string{"from", "to"} {
		printField(paint, field, paint.ref(strings.Join(list(record, field), ", ")))
	}
	printField(paint, "redacted", paint.ref(redactionCounts(record)))
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
	fmt.Printf("  %s\n", paint.key("output"))
	// One line at a time and escaped, never quoted or truncated: this is the text
	// the operator came to read. redact.Feed already took the colour and the CSI
	// on the way in, so what is left to escape is a bare "\r" or a stray ESC.
	for line := range strings.SplitSeq(strings.TrimRight(output, "\n"), "\n") {
		fmt.Printf("    %s\n", paint.token(termsafe.Line(line)))
	}
	if truncated, _ := boolean(record, "output_truncated"); truncated {
		fmt.Printf("    %s\n", paint.dim("[truncated at the record cap]"))
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

// The zone is in the header because the times below are local and the log_id
// beside them is UTC.
const dateLayout = "2006-01-02 MST"

// stampLayout is one moment in full, for a line that stands on its own rather
// than under a day heading: dateLayout's day and zone with the time `logs`
// prints against it. The approval prompt is the one place that needs it, a
// question being read without the surrounding day the log has.
const stampLayout = "2006-01-02 15:04:05 MST"

// startedAt is when the record's subject happened: started_at where the record
// has one, which is the child's fork rather than the moment the line was
// written, and otherwise the `at` every other record carries.
func startedAt(record map[string]any) time.Time {
	for _, field := range []string{"started_at", "at"} {
		if seconds, ok := num(record, field); ok {
			return time.Unix(int64(seconds), 0)
		}
	}
	return time.Time{}
}

// clockTime is local, the log being read against what somebody remembers doing.
func clockTime(record map[string]any) string {
	at := startedAt(record)
	if at.IsZero() {
		return "        "
	}
	return at.Format("15:04:05")
}

// matchesID compares the log_id as it is printed, so what is on screen pastes
// back.
func matchesID(record map[string]any, want string) bool {
	return str(record, "log_id") == want
}

// describePeer renders the caller from pid, uid and gid, resolving the uid to a
// name where the account still exists.
func describePeer(record map[string]any) string {
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

// humanBytes keeps a size to three significant figures; this column is for
// judging scale.
func humanBytes(n int64) string {
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

func str(record map[string]any, key string) string {
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

// pad is one column of the listing, widened to width. A value already that
// wide still gets a space, or it runs into the column after it. Counted in
// runes, not bytes: the ellipsis a cut record's fields end with is three bytes
// and one column.
func pad(text string, width int) string {
	spent := utf8.RuneCountInString(text)
	if spent >= width {
		return text + " "
	}
	return text + strings.Repeat(" ", width-spent)
}
