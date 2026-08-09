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
	"path/filepath"
	"strings"

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
			if str(record, "log_id") == id {
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
	for _, record := range records {
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

// summarise is one record on one line: what ran, how it ended, and the id to
// ask for the rest of it.
func summarise(record map[string]any, paint palette) string {
	var b strings.Builder
	b.WriteString(paint.dim(str(record, "log_id")))
	b.WriteString("  ")
	b.WriteString(paint.bold(pad(str(record, "op"), 6)))
	b.WriteString(exitLabel(record, paint))
	if peer := str(record, "peer"); peer != "" {
		b.WriteString("  " + paint.dim(peer))
	}
	if cmd := joinCmd(record); cmd != "" {
		b.WriteString("  " + cmd)
	}
	return b.String()
}

// printRecord is the whole of one record, output included.
func printRecord(record map[string]any, paint palette) {
	fmt.Println(summarise(record, paint))
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

// exitLabel is blank for a record that has no exit code, which a redact
// request does not: it ran no command.
func exitLabel(record map[string]any, paint palette) string {
	code, ok := record["exit_code"].(float64)
	if !ok {
		return "      "
	}
	label := fmt.Sprintf("exit %-2d", int(code))
	if code == 0 {
		return paint.ok(label)
	}
	return paint.bad(label)
}

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
