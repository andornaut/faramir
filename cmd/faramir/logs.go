package main

// faramir logs: read the audit log without having to remember where it is.
//
// Root only, and not brokered: the log is 0600 faramir-broker, and serving it
// over the broker socket would hand it to the group the agent runs as.
//
// It holds no secret value (output was recorded after redaction, refs are names,
// and nothing is substituted into argv), so this prints what it finds.
// Rotated files are not read; name one to zless.

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
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/termsafe"
)

// How many records a bare `faramir logs` lists.  A screenful; a specific record
// is asked for by log_id.
const defaultLogCount = 20

func cmdLogs(args []string) int {
	fs := newFlagSet("logs", "logs [options] [LOG-ID]")
	configPath := fs.String("config", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	fs.StringVar(configPath, "c", "", "config file (shorthand)")
	logPath := fs.String("path", "", "audit log to read (default: the one the config names)")
	count := fs.Int("count", defaultLogCount, "how many recent records to list")
	fs.IntVar(count, "n", defaultLogCount, "how many recent records to list (shorthand)")
	socket := fs.String("socket", socketDefault(), "broker socket to ask where the install is ($FARAMIR_SOCKET)")
	asJSON := fs.Bool("json", false, "print the records as JSON")
	when := fs.String("color", "auto", "colourise: auto, always or never")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 1 {
		return usageError(fs, "faramir logs: at most one log-id")
	}
	paint, err := newPalette(*when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 2
	}

	// Refused rather than attempted: otherwise a bare permission error on a
	// path the caller did not name.
	if !requireRoot("logs", "the audit log is readable only by the broker and by root") {
		return 1
	}

	path := *logPath
	if path == "" {
		cfg, err := config.Load(resolveConfig(*configPath, *socket))
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		path = cfg.Audit.LogPath
	}

	if id := fs.Arg(0); id != "" {
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
		if *asJSON {
			return printJSON(record)
		}
		printRecord(record, paint)
		return 0
	}

	records, skipped, err := tailRecords(path, *count)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	reportSkipped(path, skipped)
	if *asJSON {
		// An empty listing is a JSON empty array, not null: a caller parsing stdout
		// gets a value either way.
		if records == nil {
			records = []map[string]any{}
		}
		return printJSON(records)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, emptyReason(path, *count))
		return 0
	}
	// Once per day rather than on every line, which would crowd out the columns
	// that differ.
	day := ""
	for _, record := range records {
		if at := startedAt(record); !at.IsZero() && at.Format(dateLayout) != day {
			day = at.Format(dateLayout)
			fmt.Println(paint.dim(day))
		}
		fmt.Println(summarise(record, paint))
	}
	return 0
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
		return nil, fmt.Errorf("no audit log at %s. Nothing has been brokered on "+
			"this host, or [audit] log_path names somewhere else", path)
	}
	return fh, err
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

// tailRecords is the last count records, parsed.
//
// The last count *lines* are kept as bytes and parsed at the end, so what this
// holds is bounded by what was asked for rather than by how long the log is.
// Parsing every record to throw all but twenty away is what made `faramir logs
// -n 3` cost a gigabyte on a log an agent had grown; scanning bytes is cheap and
// bounded, and the parse is what is not.
//
// A count of zero or less asks for nothing and gets nothing: treating it as "no
// limit" would print the whole log to somebody who asked for none of it.  The
// log is still opened, so a host with no log at all says so rather than
// reporting the count the caller passed as an empty log.
//
// The ring grows to what the log holds rather than to what -n asked for, so
// `-n 500000000` on a log of ten records costs ten records.  Sized up front it
// was an allocation the caller named: a number the flag accepts, times a slice
// header, before a single line had been read.
// ringCapMax bounds what the ring is sized to up front.  --count is a number the
// caller names and the flag accepts any int, so sizing to it costs a slice
// header times that number before a single line has been read; the ring grows to
// what the log actually holds instead.
const ringCapMax = 1024

func ringCap(count int) int { return min(count, ringCapMax) }

func tailRecords(path string, count int) ([]map[string]any, int, error) {
	if count <= 0 {
		fh, err := openAuditLog(path)
		if err != nil {
			return nil, 0, err
		}
		_ = fh.Close()
		return nil, 0, nil
	}
	ring, next, filled := make([][]byte, 0, ringCap(count)), 0, false
	if err := scanAuditLog(path, func(line []byte) bool {
		// Copied: the reader owns its buffer and reuses it on the next line.
		kept := append([]byte(nil), line...)
		if !filled && len(ring) < count {
			ring = append(ring, kept)
			if len(ring) == count {
				filled = true
			}
			return true
		}
		ring[next] = kept
		if next++; next == count {
			next = 0
		}
		return true
	}); err != nil {
		return nil, 0, err
	}

	ordered := ring
	if filled {
		ordered = append(append([][]byte{}, ring[next:]...), ring[:next]...)
	}
	var records []map[string]any
	skipped := 0
	for _, line := range ordered {
		record, lost := parseLine(line)
		switch {
		case record != nil:
			records = append(records, record)
		case lost:
			skipped++
		}
	}
	return records, skipped, nil
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
	return fmt.Sprintf("%s holds no records to show", path)
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
	printField(paint, "caller", describePeer(record))
	// outcome is the approval's own reason (why it was refused, or that it was
	// approved) and exec_log_id is the command's record, so an approval reads in
	// both directions.
	// Rendered, not printed: cwd is the caller's, error and outcome quote what
	// failed (an approval's reason carries the command it was refused for, and the
	// names of the processes that held the host), so all three carry text chosen
	// by the account this log exists to hold to account.
	for _, field := range []string{"cwd", "error", "outcome", "exec_log_id"} {
		if value := str(record, field); value != "" {
			printField(paint, field, termsafe.Line(value))
		}
	}
	printField(paint, "refs", paint.ref(strings.Join(list(record, "env_refs"), ", ")))
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

// redactionCounts is per token, for the detail view; the listing sums them.
func redactionCounts(record map[string]any) string {
	var out []string
	for _, entry := range redactions(record) {
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
			return at.UTC().Local()
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
	if account, err := user.LookupId(fmt.Sprint(int(uid))); err == nil {
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
// that wide still gets a space: without one it runs into the column after it,
// which is what an op name longer than its column did (`ask_approvalrefused`),
// and a row whose columns have merged is a row that is read wrong.
func pad(text string, width int) string {
	if len(text) >= width {
		return text + " "
	}
	return text + strings.Repeat(" ", width-len(text))
}
