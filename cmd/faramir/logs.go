package main

// faramir logs: read the audit log without having to remember where it is.
//
// Root only, and not brokered: the log is 0600 faramir-broker, and serving it
// over the broker socket would hand it to the group the agent runs as.
//
// It holds no secret value (output was recorded after redaction, refs are names,
// and nothing is substituted into argv), so this prints what it finds.
//
// Which file it reads is the config's to say, through [audit] log_path, and
// there is no flag naming another: a reader pointed at a path by hand is a
// typo away from reporting a host as quiet, and --watch would wait on that
// path for ever.  --config and FARAMIR_CONFIG move it, and both name a file
// that has to exist.  Rotated files are not read; name one to zless.
//
// --watch is the one place rotation is followed rather than ignored: a watcher
// left running across a logrotate run reopens the path and carries on, and one
// started before the first brokered command waits for the log to be created.

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

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/termsafe"
)

// How many records a bare `faramir logs` lists.  A screenful; a specific record
// is asked for by log_id.
const defaultLogCount = 20

// watchPoll is how often a watcher looks for what has been appended.  Records
// arrive when a brokered command finishes, so this is a human's idea of "as it
// happens" rather than a rate anything depends on: an interval short enough that
// a row follows the command that wrote it, and long enough that a terminal left
// open overnight is not a stat per hundredth of a second.
const watchPoll = 500 * time.Millisecond

type logsFlags struct {
	configPath string
	count      int
	socket     string
	asJSON     bool
	watch      bool
	when       string
}

func newLogsCmd() *cobra.Command {
	var f logsFlags
	c := &cobra.Command{
		Use:     "logs [options] [LOG-ID]",
		Short:   "show the audit log: what ran, against which refs, and how it ended",
		GroupID: groupProvisioning,
		Args:    atMostOneArg("log-id"),
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runLogs(f, args)) },
	}
	c.Flags().StringVarP(&f.configPath, "config", "c", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	c.Flags().IntVarP(&f.count, "count", "n", defaultLogCount, "how many recent records to list")
	c.Flags().StringVar(&f.socket, "socket", socketDefault(), "broker socket to ask where the install is ($FARAMIR_SOCKET)")
	c.Flags().BoolVar(&f.asJSON, "json", false, "print the records as JSON")
	c.Flags().BoolVar(&f.watch, "watch", false, "keep printing records as they are appended")
	c.Flags().StringVar(&f.when, "color", "auto", "colourise: auto, always or never")
	return c
}

func runLogs(f logsFlags, args []string) int {
	paint, err := newPalette(f.when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 2
	}

	// A log-id is one record, already written; there is nothing to wait for, and a
	// command that printed it and then sat there would look like it had hung.
	// Refused here rather than below the root check, so the answer is the same
	// whoever typed it.
	if f.watch && firstArg(args) != "" {
		fmt.Fprintln(os.Stderr, "faramir logs: --watch prints records as they arrive, "+
			"so it takes no log-id. Drop one or the other")
		return 2
	}

	// Refused rather than attempted: otherwise a bare permission error on a
	// path the caller did not name.
	if !requireRoot("logs", "the audit log is readable only by the broker and by root") {
		return 1
	}

	cfg, err := config.Load(resolveConfig(f.configPath, f.socket))
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
			return printJSON(record)
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
		return printJSON(records)
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
// each day.  The header is once per day rather than on every line, which would
// crowd out the columns that differ, and the day it last printed is state: a
// watcher left running prints a new header when the day turns under it.
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
// them, until it is interrupted.  It returns only on an error it cannot read
// past: there is no end to a log that is still being written.
//
// One reader throughout, positioned at the end of the file the backlog was read
// from, so a record written while the backlog is being printed is shown once
// rather than twice or not at all.
func runWatch(path string, f logsFlags, paint palette) int {
	follow, err := openFollower(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	defer follow.close()

	printer := logPrinter{paint: paint}
	skipped := 0
	// A record on the way past.  --json prints one value per record rather than the
	// array the listing prints: there is no last record to close an array after, and
	// a stream of values is what a decoder reading stdout can consume as they
	// arrive.
	emit := func(line []byte) {
		record, lost := parseLine(line)
		switch {
		case record == nil:
			if lost {
				skipped++
			}
		case f.asJSON:
			_ = printJSON(record)
		default:
			printer.row(record)
		}
	}

	// The backlog, read through the same reader: what is already in the log, kept
	// as bytes and parsed at the end, exactly as the listing does it.
	backlog := newLineRing(f.count)
	if err := follow.drain(backlog.add); err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	records, lost := parseLines(backlog.ordered())
	reportSkipped(path, lost)
	// Said only where the count asked for records: `--watch -n 0` asked for the
	// arriving ones alone, and emptyReason's advice would be an answer to a
	// question nobody put.  A log that is not there yet is its own answer, and
	// not the listing's: this waits for it rather than reporting it.
	switch {
	case !follow.following():
		fmt.Fprintf(os.Stderr, "no audit log at %s yet: nothing has been brokered "+
			"on this host, and the first record creates it\n", path)
	case len(records) == 0 && f.count > 0:
		fmt.Fprintln(os.Stderr, emptyReason(path, f.count))
	}
	for _, record := range records {
		if f.asJSON {
			_ = printJSON(record)
			continue
		}
		printer.row(record)
	}
	fmt.Fprintf(os.Stderr, "watching %s for new records. Ctrl-C to stop.\n", path)

	for {
		if err := follow.drain(emit); err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		// Per pass rather than per line: a run of lines that will not parse is one
		// report, and the count is what makes it a report worth reading.
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
				// Straight round again rather than waiting a poll: the file at the path is
				// a new one, read from its start.
				continue
			case !os.IsNotExist(err):
				fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
				return 1
			}
			// The file went between the stat and the open, so the follower is detached
			// and reads nothing until one is back at the path.  A pass that finds one
			// reports a rotation again and reopens onto it.
		}
		time.Sleep(watchPoll)
	}
}

// printJSON writes a record, or a list of them, to stdout as indented JSON: the
// machine-readable form of what the text listing shows.  The fields hold no
// secret value (output was recorded after redaction, refs are names, nothing is
// substituted into argv), which is why logs prints what it finds.
func printJSON(v any) int {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	fmt.Println(string(body))
	return 0
}

// scanAuditLog calls visit with each line of the log, in order, and stops early
// when visit returns false.  It holds one line at a time, so what it costs is
// the largest record rather than the file: [audit] max_record_bytes bounds a
// line at the writer, which is the only place that can bound it.
//
// No ceiling on a line's length here, and none is needed.  A ceiling in a reader
// is a size the agent picks -- a record carries its command's output, and '<',
// '>', '&' and every C0 control cost six bytes apiece once encoded -- and
// exceeding it would not lose one record: the read would stop there, withholding
// every record before and after it too.
//
// visit is handed the line with its newline where it had one.  A line with none
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

// openAuditLog is the log, with the missing-file case named: every caller of
// this is examining an install, and "no such file" alone reads as a path typo
// rather than as a host where nothing has been brokered.
func openAuditLog(path string) (*os.File, error) {
	fh, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		return nil, missingLog(path)
	}
	return fh, err
}

// missingLog is that message on its own, for a caller that opens the log itself
// because it has to tell "not there" from every other reason a file will not
// open: os.IsNotExist does not survive being rewritten into a sentence.
func missingLog(path string) error {
	return fmt.Errorf("no audit log at %s. Nothing has been brokered on "+
		"this host, or [audit] log_path names somewhere else", path)
}

// parseLine is one line as a record, and whether losing it means a record was
// lost.  The one unparseable line that is not evidence of a loss is the last,
// with no newline on the end: nothing finished writing it.  A line that ends
// properly and will not parse is a record gone.
//
// A nil record counts as lost too.  "null" is valid JSON and unmarshals into a
// map without error, leaving it nil, so testing the error alone drops that line
// silently: the one line this reader would neither show nor count.
func parseLine(line []byte) (record map[string]any, lost bool) {
	if err := json.Unmarshal(line, &record); err != nil || record == nil {
		return nil, bytes.HasSuffix(line, []byte("\n"))
	}
	return record, false
}

// ringCapMax bounds what the ring is sized to up front.  --count is a number the
// caller names and the flag accepts any int, so sizing to it costs a slice
// header times that number before a single line has been read; the ring grows to
// what the log actually holds instead.
const ringCapMax = 1024

func ringCap(count int) int { return min(count, ringCapMax) }

// lineRing keeps the last count lines it was given.  A count of zero or less
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

// tailRecords is the last count records, parsed.
//
// The last count *lines* are kept as bytes and parsed at the end, so what this
// holds is bounded by what was asked for rather than by how long the log is.
// Scanning bytes is cheap and bounded; parsing every record to throw all but
// twenty away is what is not, and costs the whole log on one an agent has grown.
//
// A count of zero or less asks for nothing and gets nothing: treating it as "no
// limit" would print the whole log to somebody who asked for none of it.  The
// log is still opened, so a host with no log at all says so rather than
// reporting the count the caller passed as an empty log.
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

// follower reads a log that is still being written.  It holds the reader open
// between passes, so what it costs on a quiet host is a stat per poll rather
// than a re-read of the file.
//
// Complete lines only: a record still being appended is held until its newline
// arrives.  scanAuditLog does the opposite -- it hands the last line over
// whether or not it ends -- because a listing is a reading of a file as it
// stands, while a watcher is going to see the rest of that line in a moment.
//
// A follower with no file is a state rather than a failure: the path holds
// none between logrotate's rename and the next record, and none at all on a
// host where nothing has been brokered yet.  Detached, it reads nothing and
// reports no rotation until a file is there, and the next pass attaches to it.
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

// open is the raw error, not openAuditLog's sentence: the caller has to tell a
// path with no file at it from a path that cannot be opened at all, and the
// first of those is a pass to wait rather than a failure.
//
// Every field is cleared first, so a failure leaves a detached follower rather
// than one still holding the reader it just closed.
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

// reopen is the file the path names now, read from its start.  The half-written
// line held from the file before it is dropped with it: it belongs to a record
// that is in the rotated file, and pasting it onto the first line of the new one
// would make a line that is neither.
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
// when it reaches the end of what has been written.  Blank lines are skipped, as
// in scanAuditLog: they carry no record either way.
//
// Nothing to read while detached, which is not an error: the caller polls on,
// and rotated() is what says a file has appeared.
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

// rotated is whether the file being read is no longer the log.
//
// Two ways it stops being the log.  logrotate's rule renames it and the broker
// creates the next one by writing a record, so the path comes to name a
// different file; and anything that empties the log in place leaves the same
// file shorter than what has already been read.  Either way the reader is on a
// file nothing will append to again, and every record written from here lands
// somewhere it is not looking.
//
// A path with nothing at it is neither: that is the gap between logrotate's
// rename and the next record, and the file it is reading is still the one those
// records were written to.
//
// A file at a path a detached follower holds counts, which is what attaches it:
// os.SameFile is false against the nil info of a follower that has none, so the
// first record written on a host where nothing had been brokered reads as a
// rotation and the caller reopens onto it.
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

// findRecord is the first record whose id matches, or nil.  It parses one line
// at a time and keeps only the match, so looking a record up costs the same on a
// log of any length.
//
// First match, and with a log_id distinct by construction there is only ever
// one: see audit.NewLogID.
func findRecord(path, id string) (map[string]any, int, error) {
	var found map[string]any
	skipped := 0
	err := scanAuditLog(path, func(line []byte) bool {
		record, lost := parseLine(line)
		if lost {
			skipped++
		}
		if record != nil && matchesID(record, id) {
			found = record
			return false
		}
		return true
	})
	return found, skipped, err
}

// reportSkipped says what was not shown.  Swallowing it would be the worse
// failure: a listing that looks complete when a record is missing from it is a
// listing that answers the question wrongly, and this file exists to answer that
// question.  Since internal/audit takes back a short write, a line that will not
// parse now means the log was written by something else, or damaged after the
// fact.
func reportSkipped(path string, skipped int) {
	if skipped == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "faramir logs: %s: %d line(s) do not parse and are not shown. "+
		"The broker writes one record per line and takes back a write that lands "+
		"short, so a line like this was written by something else or damaged "+
		"afterwards\n", path, skipped)
}

// emptyReason is why the listing is empty.  A count that asked for nothing and
// a log that holds nothing are different answers, and one message for both
// reports the state of the host to somebody who typed -n 0: the log named there
// may be full of records.  An absent log is neither, and is reported before
// this by tailRecords opening it whatever the count was.
func emptyReason(path string, count int) string {
	if count <= 0 {
		return fmt.Sprintf("--count %d asks for no records. Pass a positive count to "+
			"list some, or a log-id to look one up", count)
	}
	return path + " holds no records to show"
}

// shortIDWidth is the hex tail of a log_id: the writer's nonce and its counter,
// which is what audit.NewLogID puts after the timestamp.
const shortIDWidth = 10

// summarise is one record on one line: when, what, how it ended, how many
// values it touched, and the id to ask for the rest.  The id is the trailing
// hex, the timestamp being in the row already; lookup takes either form.
func summarise(record map[string]any, paint palette) string {
	var b strings.Builder
	b.WriteString(paint.dim(pad(shortID(record), shortIDWidth)))
	b.WriteString(" " + clockTime(record) + "  ")
	b.WriteString(paint.bold(pad(str(record, "op"), 7)))
	b.WriteString(paintOutcome(record, paint))
	b.WriteString(paint.ref(pad(redactionTotal(record), 12)))
	b.WriteString(detail(record))
	return strings.TrimRight(b.String(), " ")
}

// detail is the command for an exec, the size of the text for a redact, and the
// managed file for an edit or a rekey, each of which would otherwise be a bare
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

// outcome is how an exec ended, and whether that is a failure.  A redact ran no
// command, so it has neither.
func outcome(record map[string]any) (string, bool) {
	if timedOut, _ := boolean(record, "timed_out"); timedOut {
		return "timed out", true
	}
	// An approval ends in an answer rather than an exit code.  A refusal is the
	// one painted as a failure, not because refusing is wrong (it is the safe
	// answer) but because something asked, and that is what an operator is scanning
	// for.
	if approved, ok := boolean(record, "approved"); ok {
		if approved {
			return "approved", false
		}
		return "refused", true
	}
	// The refusal's own code, which is the string the caller was answered with:
	// an operator handed a log_id can confirm they are reading the refusal that
	// was cited, and the listing can be scanned for one kind of refusal.
	if refused := str(record, "refused"); refused != "" {
		return refused, true
	}
	code, ok := num(record, "exit_code")
	if !ok {
		// No exit code and an error: the broker recorded that this never became a
		// finished command.  Named generically because the two records shaped this
		// way differ in how far they got -- one could not resolve the program, the
		// other lost the executor after the child was spawned -- and the error is
		// on the detail view for both.  Blank here would render them as a command
		// that ran and did nothing.
		if str(record, "error") != "" {
			return "failed", true
		}
		return "", false
	}
	label := fmt.Sprintf("exit %d", int(code))
	if seconds, ok := num(record, "duration_sec"); ok {
		label += fmt.Sprintf(" %.2fs", seconds)
	}
	return label, code != 0
}

// redaction is one token and how often it stood in for its value.
type redaction struct {
	token string
	count int
}

// redactions is the record's counts, read once for both the listing's sum and
// the detail view's per-token line: two readers of the same array disagreeing
// about its shape would print two different answers to the same question.
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
// tokens: a credential was used, without saying which value it had.
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
// nothing under the label.  The label's width is stated once here: a row whose
// label column is a different width from the row above it is read as a
// different kind of row.
func printField(paint palette, label, value string) {
	const labelWidth = 10
	if value == "" {
		return
	}
	fmt.Printf("  %s %s\n", paint.key(pad(label, labelWidth)), value)
}

// printRecord is the whole of one record, output included.
func printRecord(record map[string]any, paint palette) {
	fmt.Println(summarise(record, paint))
	printField(paint, "id", str(record, "log_id"))
	// Above the fields it qualifies rather than under them: what a reduced record
	// holds was cut to fit the cap, so a reader has to know that before believing
	// a short argv or a list of refs that ends where the record ran out of room.
	if reduced, _ := boolean(record, "record_reduced"); reduced {
		printField(paint, "reduced", paint.dim(
			"fields were cut to fit [audit] max_record_bytes"))
	}
	printField(paint, "caller", describePeer(record))
	// The labels are not all the field names.  argv0_path is what root or the
	// executor actually ran, which can differ from the command: a relative argv[0]
	// resolves against the cwd, and that is a tree the coding agent writes.  It
	// reads as `program`, the word the approval question uses for the same thing,
	// and sits under the cwd it resolved against.
	//
	// outcome is the approval's own reason (why it was refused, or that it was
	// approved), reason is why a refusal that never reached a command refused it,
	// and exec_log_id is the command's record, so an approval reads in both
	// directions.
	//
	// Rendered, not printed: all of these carry text chosen by the account this
	// log exists to hold to account -- the cwd and the program are the caller's,
	// and error and outcome quote what failed (an approval's reason carries the
	// command it was refused for, and the names of the processes that held the
	// host).
	for _, row := range []struct{ field, label string }{
		{"cwd", "cwd"}, {"argv0_path", "program"}, {"error", "error"},
		{"outcome", "outcome"}, {"reason", "reason"}, {"exec_log_id", "exec_log_id"},
	} {
		if value := str(record, row.field); value != "" {
			printField(paint, row.label, termsafe.Line(value))
		}
	}
	printField(paint, "refs", paint.ref(envRefs(record)))
	// A rekey's recipients, which are the whole of what it changed: who could
	// read that file before, and who can now.  Public keys, so printing them
	// discloses nothing the ciphertext does not already carry.
	for _, field := range []string{"from", "to"} {
		printField(paint, field, paint.ref(strings.Join(list(record, field), ", ")))
	}
	printField(paint, "redacted", paint.ref(redactionCounts(record)))
	output, _ := record["output"].(string)
	if output == "" {
		return
	}
	fmt.Printf("  %s\n", paint.key("output"))
	// One line at a time and escaped, never quoted or truncated: this is the text
	// the operator came to read.  redact.Feed already took the colour and the CSI
	// on the way in, so nothing legible is lost here; what is left to escape is a
	// bare "\r" and a stray ESC, either of which rewrites what the reader sees.
	for line := range strings.SplitSeq(strings.TrimRight(output, "\n"), "\n") {
		fmt.Printf("    %s\n", paint.token(termsafe.Line(line)))
	}
	if truncated, _ := boolean(record, "output_truncated"); truncated {
		fmt.Printf("    %s\n", paint.dim("[truncated at [audit] max_record_bytes]"))
	}
}

// envRefs is what the command asked to be injected, as NAME=ref.
//
// The record holds an object rather than a list, NAME -> ref, and the pairing
// is the whole of what an operator checks an injection against: which variable
// carried which ref.  Neither half is a value -- the ref names a secret and the
// store holds it -- so this prints what the record carries.
//
// Sorted by variable name, so the same command reads the same way every time
// rather than in whatever order the map iterated.
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
	// Rendered like every other field taken from a record: both halves are
	// bounded by what the protocol accepts, but a log written by something else
	// is one of the things this reader is for.
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
// coding agent's own text, and this is printed to the operator's.
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

// startedAt is when the command ran: started_at where there is one, otherwise
// the log_id, which carries the same instant.  A redact record has no
// started_at.
func startedAt(record map[string]any) time.Time {
	if seconds, ok := num(record, "started_at"); ok {
		return time.Unix(int64(seconds), 0)
	}
	id := str(record, "log_id")
	if stamp, _, found := strings.Cut(id, "Z-"); found {
		if at, err := time.Parse("2006-01-02T15:04:05", stamp); err == nil {
			// Local on purpose: the log_id is UTC and the listing is read against
			// what somebody remembers doing on this host, which is its own clock.
			return at.UTC().Local() //nolint:gosmopolitan // the operator's own clock is the point
		}
	}
	return time.Time{}
}

// clockTime is local rather than the log_id's UTC, the log being read against
// what somebody remembers doing.
func clockTime(record map[string]any) string {
	at := startedAt(record)
	if at.IsZero() {
		return "        "
	}
	return at.Format("15:04:05")
}

// shortID is the hex tail of a log_id, the rest being the timestamp already in
// the row.
func shortID(record map[string]any) string {
	id := str(record, "log_id")
	if _, tail, found := strings.Cut(id, "Z-"); found {
		return tail
	}
	return id
}

// matchesID accepts the whole log_id or the short tail, so what is on screen
// can be pasted back.
func matchesID(record map[string]any, want string) bool {
	return str(record, "log_id") == want || shortID(record) == want
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

// num is a recorded number and whether the field was there.  Every number in a
// record comes back from encoding/json as a float64, whatever it was written
// as, and the callers here want to tell an absent exit code from an exit code
// of zero.
func num(record map[string]any, key string) (float64, bool) {
	value, ok := record[key].(float64)
	return value, ok
}

// boolean is a recorded flag and whether the field was there.  `flag` is the
// standard library's package name here, and this file's callers are already
// reading command-line flags by that word.
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

// pad is one column of the listing, widened to width.  A value that is already
// that wide still gets a space: without one it runs into the column after it
// (`ask_approval` overruns the op column, and the row reads
// `ask_approvalrefused`), and a row whose columns have merged is read wrong.
// Counted in runes, not bytes: a value carrying the ellipsis a cut record's
// fields end with is three bytes and one column, and a column padded by its
// byte count is one that does not line up with the row above it.
func pad(text string, width int) string {
	spent := utf8.RuneCountInString(text)
	if spent >= width {
		return text + " "
	}
	return text + strings.Repeat(" ", width-spent)
}
