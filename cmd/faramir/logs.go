package main

// faramir logs: read the audit log without having to remember where it is.
//
// Root only, and not brokered: the log is 0600 faramir-broker, and serving it
// over the broker socket would hand it to the group the agent runs as.
//
// It holds no secret value -- output was recorded after redaction, refs are
// names, and nothing is substituted into argv -- so this prints what it finds.
// Rotated files are not read; name one to zless.

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

// How many records a bare `faramir logs` lists.  A screenful; a specific record
// is asked for by log_id.
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

	// Refused rather than attempted: otherwise a bare permission error on a
	// path the caller did not name.
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

	records = tailRecords(records, *count)
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

// readAuditLog parses the log as JSONL, skipping a line that does not parse: a
// read concurrent with the daemon's append gives a torn final line, which must
// not hide the records before it.
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
	// max_record_bytes (4MiB by default); bufio's own default is 64KiB.
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
// values it touched, and the id to ask for the rest.  The id is the trailing
// hex, the timestamp being in the row already; lookup takes either form.
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

// tailRecords is the last count records.  A count of zero or less asks for
// nothing and gets nothing: treating it as "no limit" would print the whole log
// to someone who asked for none of it.
func tailRecords(records []map[string]any, count int) []map[string]any {
	switch {
	case count <= 0:
		return nil
	case count < len(records):
		return records[len(records)-count:]
	}
	return records
}

// detail is the command for an exec, the size of the text for a redact, and the
// managed file for an edit or a rekey, each of which would otherwise be a bare
// row naming only the op.
func detail(record map[string]any) string {
	if cmd := joinCmd(record); cmd != "" {
		return cmd
	}
	if size, ok := record["input_bytes"].(float64); ok {
		return humanBytes(int64(size)) + " in"
	}
	if file := str(record, "file"); file != "" {
		return file
	}
	if detail := str(record, "error"); detail != "" {
		return detail
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
	if timedOut, _ := record["timed_out"].(bool); timedOut {
		return "timed out", true
	}
	// An elevation ends in an answer rather than an exit code.  A refusal is the
	// one painted as a failure, not because refusing is wrong -- it is the safe
	// answer -- but because something asked, and that is what an operator is
	// scanning for.
	if approved, ok := record["approved"].(bool); ok {
		if approved {
			return "approved", false
		}
		return "refused", true
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
// tokens: a credential was used, without saying which value it had.
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
	// outcome is the elevation's own reason -- why it was refused, or that it was
	// approved -- and exec_log_id is the command's record, so an approval reads
	// in both directions.
	for _, field := range []string{"cwd", "error", "outcome", "exec_log_id"} {
		if value := str(record, field); value != "" {
			fmt.Printf("  %s %s\n", paint.key(pad(field, 10)), value)
		}
	}
	if refs := list(record, "env_refs"); len(refs) > 0 {
		fmt.Printf("  %s %s\n", paint.key(pad("refs", 10)), paint.ref(strings.Join(refs, ", ")))
	}
	// A rekey's recipients, which are the whole of what it changed: who could
	// read that file before, and who can now.  Public keys, so printing them
	// discloses nothing the ciphertext does not already carry.
	for _, field := range []string{"from", "to"} {
		if recipients := list(record, field); len(recipients) > 0 {
			fmt.Printf("  %s %s\n", paint.key(pad(field, 10)), paint.ref(strings.Join(recipients, ", ")))
		}
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

// redactionCounts is per token, for the detail view; the listing sums them.
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

// The zone is in the header because the times below are local and the log_id
// beside them is UTC.
const dateLayout = "2006-01-02 MST"

// startedAt is when the command ran: started_at where there is one, otherwise
// the log_id, which carries the same instant.  A redact record has no
// started_at.
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
	uid, _ := fields["uid"].(float64)
	pid, _ := fields["pid"].(float64)
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
