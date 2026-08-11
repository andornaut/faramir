// Package audit writes the audit log, readable only by the broker's uid.
//
// It holds no secret value: output is recorded after redaction, the refs are
// names, and nothing is ever substituted into argv.  What auditing needs is who
// ran what, when, against which refs, and to what effect; the redaction counts
// are how a credential's arrival is confirmed.
//
// The response carries a log_id pointing into this file, so the agent can cite a
// record it cannot read.
//
// One caveat: a value refused at load is absent from the redactor, so if it
// reaches the output it arrives here in plaintext too.  `faramir broker --check`
// names every such ref.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/config"
)

func NewLogID() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("2006-01-02T15:04:05Z") + "-" + hex.EncodeToString(b[:])
}

// Log is an append-only JSONL sink.  One record per brokered invocation.
type Log struct {
	config config.AuditConfig
	mu     sync.Mutex
	ready  bool
}

func NewLog(cfg config.AuditConfig) *Log { return &Log{config: cfg} }

func (l *Log) ensure() error {
	if l.ready {
		return nil
	}
	path := l.config.LogPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// An explicit mode rather than umask-plus-touch: the umask is process-wide,
	// and a child forked during that window would inherit it.
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = fh.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	l.ready = true
	return nil
}

// Write records one invocation together with its redacted output.
func (l *Log) Write(record map[string]any, output string) {
	payload := make(map[string]any, len(record)+2)
	maps.Copy(payload, record)
	limit := l.config.MaxRecordBytes
	if len(output) > limit {
		payload["output_truncated"] = true
		output = cutAtRune(output, limit)
	}
	payload["output"] = output

	line, err := json.Marshal(payload)
	if err != nil {
		log.Printf("audit marshal failed: %v", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensure(); err != nil {
		log.Printf("cannot open audit log %s: %v", l.config.LogPath, err)
		return
	}
	// O_CREATE though ensure() made the file: logrotate renames it away and
	// ensure() does not run again.  Opened per write rather than held, which is
	// what makes a plain rename safe with no copytruncate and no signal.
	fh, err := os.OpenFile(l.config.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// Never fail a request because logging broke.
		log.Printf("audit write failed: %v", err)
		return
	}
	defer func() { _ = fh.Close() }()
	line = append(line, '\n')
	written, err := fh.Write(line)
	if err == nil {
		return
	}
	log.Printf("audit write failed: %v", err)
	if leftOpen(line, written) {
		if _, err := fh.Write([]byte{'\n'}); err != nil {
			log.Printf("audit could not terminate a torn record, so the next one "+
				"appends to it and neither reads back: %v", err)
		}
	}
}

// leftOpen reports whether a failed write left the record's line open: some of
// it landed, not all of it, and what landed does not end the line.
//
// The next record appends straight onto an open line, so one failed write takes
// two records rather than one, and the second of them is a record that was
// written successfully.  `faramir logs` skips both, an unparseable line being
// indistinguishable from the torn final one a concurrent read sees.  Closing the
// line costs a byte and keeps the loss to the record that failed.
//
// Best effort by nature: what usually stops a record is a full filesystem, which
// stops the terminator too.  It is the short write with a cause of its own that
// this keeps from spreading.
func leftOpen(line []byte, written int) bool {
	return written > 0 && written < len(line) && line[written-1] != '\n'
}

// cutAtRune returns the first limit bytes of s, backing off only far enough not
// to end on a partial rune, which JSON would record as U+FFFD.  Bounded to
// UTFMax: scanning back for the first valid prefix would discard everything
// after any invalid byte, and brokered output is raw PTY bytes.
func cutAtRune(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	cut := s[:limit]
	for i := 1; i < utf8.UTFMax && i <= len(cut); i++ {
		start := len(cut) - i
		if !utf8.RuneStart(cut[start]) {
			continue
		}
		if utf8.ValidString(cut[start:]) {
			return cut // the last rune is whole
		}
		return cut[:start]
	}
	return cut
}

// Collector accumulates the redacted stream for one invocation, with a cap of
// its own: the log may hold more of a long run than the response, but never
// anything the response would not have shown.
type Collector struct {
	limit int
	parts []string
	size  int
}

func NewCollector(limit int) *Collector { return &Collector{limit: limit} }

func (c *Collector) Add(text string) {
	if c.size >= c.limit {
		return
	}
	c.parts = append(c.parts, text)
	c.size += len(text)
}

func (c *Collector) Text() string {
	var b strings.Builder
	b.Grow(c.size)
	for _, p := range c.parts {
		b.WriteString(p)
	}
	return b.String()
}
