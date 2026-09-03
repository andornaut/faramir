package auditview

// Reading the log: the scan, the parse that counts a truncated line rather
// than failing on it, the ring a tail keeps the last N lines in, and the
// lookup of one record by id.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

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
		"this host yet, or [audit] log_path points elsewhere", path)
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

// ringCapMax bounds what the ring is sized to up front: --count accepts any
// int, so sizing to it would cost a slice header times that number before a
// line has been read. The ring grows to what the log actually holds.
const ringCapMax = 1024

func ringCap(count int) int { return min(count, ringCapMax) }

// Ring keeps the last count lines it was given. A count of zero or less
// keeps nothing, which is what --count asked for.
type Ring struct {
	count  int
	lines  [][]byte
	next   int
	filled bool
}

func NewRing(count int) *Ring {
	return &Ring{count: count, lines: make([][]byte, 0, max(ringCap(count), 0))}
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
		if record == nil || !matchesID(record, id) {
			return true
		}
		found = record
		// Stopped at the ending, which is the last of the pair: reading on would
		// scan the whole file for a record already in hand. A start half is not
		// the end of the pair, so that one reads on.
		return str(record, "op") == OpRunStarted
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
		"The broker writes one complete record per line, so these lines were "+
		"written by something else or damaged afterwards\n", path, skipped)
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
