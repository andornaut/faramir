package main

// faramir logs: read the audit log without having to remember where it is.
//
// Root only, and deliberately not brokered.  The log is 0600 faramir-broker, so
// the writer and root are the only accounts that can open it, and that is the
// point: the agent's own record of what it ran sits on the far side of a uid
// boundary from the agent.  Serving it over the broker socket would hand it to
// the shared group, which is the account the agent runs as.
//
// It holds no secret value, so this prints what it finds rather than redacting
// again.  Output was recorded after redaction, the refs are names, and argv
// never carries a value because nothing is substituted into it.
//
// Rotated files are not read.  They are the same records older than the live
// file and mostly compressed; naming one to zless is clearer than a flag that
// silently widens what a count of records covers.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/config"
)

// How many records a bare `faramir logs` lists.  A screenful: this is the
// "what has the agent been doing" view, and a specific record is asked for by
// the log_id that a response already reported.
const defaultLogCount = 20

func cmdLogs(args []string) int {
	fs := newFlagSet("logs", "logs [options] [LOG-ID]")
	configPath := fs.String("config", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	logPath := fs.String("path", "", "audit log to read (default: the one the config names)")
	count := fs.Int("n", defaultLogCount, "how many recent records to list")
	when := fs.String("color", "auto", "colourise: auto, always or never")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: faramir logs [options] [LOG-ID]")
		return 2
	}
	paint, err := newPalette(*when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	// Refused rather than attempted: as any other account this fails with a
	// bare permission error on a path the caller did not name and cannot see.
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir logs must run as root, because the audit log is "+
			"readable only by the broker and by root: try 'sudo faramir logs'")
		return 1
	}

	path := *logPath
	if path == "" {
		cfg, err := config.Load(resolveConfig(*configPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			return 1
		}
		path = cfg.Audit.LogPath
	}

	records, err := readAuditLog(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if len(records) == 0 {
		fmt.Fprintf(os.Stderr, "%s holds no records yet\n", path)
		return 0
	}

	if id := fs.Arg(0); id != "" {
		for _, record := range records {
			if matchesID(record, id) {
				printRecord(record, paint)
				return 0
			}
		}
		fmt.Fprintf(os.Stderr, "no record %s in %s. Rotated files are not searched; "+
			"a record older than the live log is in %s.1.gz and its siblings\n",
			id, path, filepath.Base(path))
		return 1
	}

	if *count < len(records) && *count > 0 {
		records = records[len(records)-*count:]
	}
	// The date once per day rather than on every line.  A log_id carries it and
	// so does each record, but repeating it twenty times crowds out the columns
	// that differ, which are the ones being read.
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

// readAuditLog parses the log as JSONL.
//
// A line that does not parse is skipped rather than fatal.  The log is appended
// to by a long-lived daemon and read here: a torn final line is what a read
// concurrent with a write looks like, and it must not hide the records before
// it.
func readAuditLog(path string) ([]map[string]any, error) {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no audit log at %s. Nothing has been brokered on "+
				"this host, or [audit] log_path names somewhere else", path)
		}
		return nil, err
	}
	defer func() { _ = fh.Close() }()

	var records []map[string]any
	scanner := bufio.NewScanner(fh)
	// A record carries its command's output, bounded by [audit]
	// max_record_bytes, whose default is 4MiB.  bufio's own default is 64KiB
	// and would stop at the first record larger than that.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return records, nil
}

// summarise is one record on one line: when, what, how it ended, how many
// values it touched, and the id to ask for the rest of it.
//
// The id is the trailing hex rather than the whole thing.  A log_id is a
// timestamp plus four hex characters, and printing the timestamp twice on every
// line pushes the columns that differ off to the right.  Lookup takes either
// form, so the short one is enough to act on.
func summarise(record map[string]any, paint palette) string {
	var b strings.Builder
	b.WriteString(paint.dim(pad(shortID(record), 5)))
	b.WriteString(" " + clockTime(record) + "  ")
	b.WriteString(paint.bold(pad(str(record, "op"), 7)))
	b.WriteString(paintOutcome(record, paint))
	b.WriteString(paint.ref(pad(redactionTotal(record), 12)))
	b.WriteString(detail(record))
	return strings.TrimRight(b.String(), " ")
}

// detail is what the record is about: the command for an exec, and the size of
// the text handed over for a redact, which would otherwise print as a bare row
// saying only that something was redacted.
func detail(record map[string]any) string {
	if cmd := joinCmd(record); cmd != "" {
		return cmd
	}
	if size, ok := record["input_bytes"].(float64); ok {
		return humanBytes(int64(size)) + " in"
	}
	if detail := str(record, "error"); detail != "" {
		return detail
	}
	return ""
}

// paintOutcome pads before colouring, never after: escapes are bytes that pad()
// would count as width, so a coloured field padded afterwards misaligns the
// column by exactly the length of the escape.
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

// outcome is how an exec ended, and whether that counts as failure.  A redact
// ran no command, so it has neither: reporting one as "exit 0" would claim
// something that was never true.
func outcome(record map[string]any) (string, bool) {
	if timedOut, _ := record["timed_out"].(bool); timedOut {
		return "timed out", true
	}
	code, ok := record["exit_code"].(float64)
	if !ok {
		return "", false
	}
	label := fmt.Sprintf("exit %d", int(code))
	if seconds, ok := record["duration_sec"].(float64); ok {
		label += fmt.Sprintf(" %.2fs", seconds)
	}
	return label, code != 0
}

// redactionTotal is how many values this record stood in for, summed across
// tokens.  The count is the point of the log: it says a credential was used
// without saying which value it had.
func redactionTotal(record map[string]any) string {
	entries, ok := record["redactions"].([]any)
	if !ok || len(entries) == 0 {
		return ""
	}
	total := 0
	for _, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		count, _ := fields["count"].(float64)
		total += int(count)
	}
	if total == 0 {
		return ""
	}
	return fmt.Sprintf("%d redacted", total)
}

// printRecord is the whole of one record, output included.
func printRecord(record map[string]any, paint palette) {
	fmt.Println(summarise(record, paint))
	fmt.Printf("  %s %s\n", paint.key(pad("id", 10)), str(record, "log_id"))
	if who := describePeer(record); who != "" {
		fmt.Printf("  %s %s\n", paint.key(pad("caller", 10)), who)
	}
	for _, field := range []string{"cwd", "error"} {
		if value := str(record, field); value != "" {
			fmt.Printf("  %s %s\n", paint.key(pad(field, 10)), value)
		}
	}
	if refs := list(record, "env_refs"); len(refs) > 0 {
		fmt.Printf("  %s %s\n", paint.key(pad("refs", 10)), paint.ref(strings.Join(refs, ", ")))
	}
	if counts := redactionCounts(record); counts != "" {
		fmt.Printf("  %s %s\n", paint.key(pad("redacted", 10)), paint.ref(counts))
	}
	output, _ := record["output"].(string)
	if output == "" {
		return
	}
	fmt.Printf("  %s\n", paint.key("output"))
	for line := range strings.SplitSeq(strings.TrimRight(output, "\n"), "\n") {
		fmt.Printf("    %s\n", paint.token(line))
	}
	if truncated, _ := record["output_truncated"].(bool); truncated {
		fmt.Printf("    %s\n", paint.dim("[truncated at [audit] max_record_bytes]"))
	}
}

// redactionCounts is per token, for the detail view.  The listing sums them
// instead: which tokens matter once you are looking at one record, and how many
// there were is what makes a row worth opening.
func redactionCounts(record map[string]any) string {
	entries, ok := record["redactions"].([]any)
	if !ok {
		return ""
	}
	var out []string
	for _, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		count, _ := fields["count"].(float64)
		out = append(out, fmt.Sprintf("%s×%d", str(fields, "token"), int(count)))
	}
	return strings.Join(out, ", ")
}

func joinCmd(record map[string]any) string {
	return strings.Join(list(record, "cmd"), " ")
}

// The zone is part of the header because the times below it are local and the
// log_id beside them is UTC.  Without it the two disagree by the offset and
// nothing on screen says why.
const dateLayout = "2006-01-02 MST"

// startedAt is when the command ran.  From started_at where there is one, and
// otherwise from the log_id, which carries the same instant: a redact record
// has no started_at, and a row with no time in a log read by time is a row that
// cannot be placed.
func startedAt(record map[string]any) time.Time {
	if seconds, ok := record["started_at"].(float64); ok {
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

// clockTime is local rather than the log_id's UTC.  The log is read by whoever
// is on the machine, against what they remember doing, and that memory is in
// the clock on their wall.
func clockTime(record map[string]any) string {
	at := startedAt(record)
	if at.IsZero() {
		return "        "
	}
	return at.Format("15:04:05")
}

// shortID is the hex tail of a log_id, which is the only part that is not the
// timestamp already in the row.
func shortID(record map[string]any) string {
	id := str(record, "log_id")
	if _, tail, found := strings.Cut(id, "Z-"); found {
		return tail
	}
	return id
}

// matchesID accepts the whole log_id or the short tail printed in the listing,
// so what is on screen can be pasted back without reconstructing the rest.
func matchesID(record map[string]any, want string) bool {
	return str(record, "log_id") == want || shortID(record) == want
}

// describePeer renders the caller.  It is an object of pid, uid and gid, and
// the uid is resolved to a name where the account still exists, an audit log
// being read long after a run and sometimes after an account is gone.
func describePeer(record map[string]any) string {
	fields, ok := record["peer"].(map[string]any)
	if !ok {
		return ""
	}
	uid, _ := fields["uid"].(float64)
	pid, _ := fields["pid"].(float64)
	who := fmt.Sprintf("uid %d", int(uid))
	if account, err := user.LookupId(fmt.Sprint(int(uid))); err == nil {
		who = fmt.Sprintf("%s (uid %d)", account.Username, int(uid))
	}
	return fmt.Sprintf("%s, pid %d", who, int(pid))
}

// humanBytes keeps a size to three significant figures.  Exact byte counts are
// what max_record_bytes is expressed in; this column is for judging scale.
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

func pad(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}
