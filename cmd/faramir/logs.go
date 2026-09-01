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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/auditview"
	"github.com/andornaut/faramir/internal/termui"
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
	paint, bad := termui.PaletteFor("logs", f.when)
	if bad != 0 {
		return bad
	}

	// A log-id names a command already recorded, so there is nothing to watch for.
	// Blocked before the root check, so the answer is the same whoever typed it.
	if f.watch && firstArg(args) != "" {
		fmt.Fprintln(os.Stderr, "faramir logs: --watch takes no log-id")
		return 2
	}

	// Blocked rather than attempted: otherwise a bare permission error on a path
	// the caller did not name.
	if !requireRoot("logs") {
		return 1
	}

	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	path := cfg.Audit.LogPath

	if id := firstArg(args); id != "" {
		record, skipped, err := auditview.Find(path, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		auditview.ReportSkipped(path, skipped)
		if record == nil {
			fmt.Fprintf(os.Stderr, "faramir logs: no record %s in %s; rotated files "+
				"(%s.1.gz and its siblings) are not searched\n",
				id, path, filepath.Base(path))
			return 1
		}
		if f.asJSON {
			return printJSON("logs", record)
		}
		auditview.PrintRecord(record, paint)
		return 0
	}

	if f.watch {
		return runWatch(path, f, paint)
	}

	records, skipped, err := auditview.Tail(path, f.count)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	auditview.ReportSkipped(path, skipped)
	if f.asJSON {
		// An empty listing is a JSON empty array, not null: a caller parsing stdout
		// gets a value either way.
		if records == nil {
			records = []map[string]any{}
		}
		return printJSON("logs", records)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, auditview.EmptyReason(path, f.count))
		return 0
	}
	printer := auditview.Printer{Paint: paint}
	for _, record := range records {
		printer.Row(record)
	}
	return 0
}

// runWatch prints the last count records and then the records appended after
// them, until it is interrupted. It returns only on an error it cannot read
// past. One reader throughout, positioned at the end of the file the backlog
// was read from, so a record written while the backlog is printing is shown
// once rather than twice or not at all.
func runWatch(path string, f logsFlags, paint termui.Palette) int {
	follow, err := auditview.OpenFollower(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	defer follow.Close()

	printer := auditview.Printer{Paint: paint}
	skipped := 0
	// A record on the way past. --json prints one value per record rather than
	// the listing's array: there is no last record to close an array after.
	emit := func(line []byte) {
		record, lost := auditview.ParseLine(line)
		switch {
		case record == nil:
			if lost {
				skipped++
			}
		case f.asJSON:
			_ = printJSON("logs", record)
		default:
			printer.Row(record)
		}
	}

	// The backlog, read through the same reader: kept as bytes and parsed at the
	// end, as the listing does it.
	backlog := auditview.NewRing(f.count)
	if err := follow.Drain(backlog.Add); err != nil {
		fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
		return 1
	}
	records, lost := auditview.ParseLines(backlog.Ordered())
	auditview.ReportSkipped(path, lost)
	// Said only where the count asked for records: `--watch -n 0` asked for the
	// arriving ones alone. A log that is not there yet is its own answer, this
	// waiting for it rather than reporting it as empty.
	switch {
	case !follow.Following():
		fmt.Fprintf(os.Stderr, "no audit log at %s yet; the first brokered "+
			"command creates it\n", path)
	case len(records) == 0 && f.count > 0:
		fmt.Fprintln(os.Stderr, auditview.EmptyReason(path, f.count))
	}
	for _, record := range records {
		if f.asJSON {
			_ = printJSON("logs", record)
			continue
		}
		printer.Row(record)
	}
	fmt.Fprintf(os.Stderr, "watching %s. Ctrl-c to stop.\n", path)

	for {
		if err := follow.Drain(emit); err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		// Per pass rather than per line: a run of lines that will not parse is one
		// report.
		auditview.ReportSkipped(path, skipped)
		skipped = 0

		rotated, err := follow.Rotated()
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir logs: %v\n", err)
			return 1
		}
		if rotated {
			switch err := follow.Reopen(); {
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
