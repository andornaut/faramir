// Package audit writes the audit log, readable only by the broker's uid.
//
// The log holds no secret value.  Output is recorded after redaction, exactly
// as the agent received it, and every other field of a record is already
// value-free: the refs are names, and argv never carries a value because
// nothing is ever substituted into it.
//
// That is a deliberate narrowing.  The log used to hold the unredacted stream,
// justified as the operator's debugging copy, and the cost was the only
// plaintext this system writes to disk: unencrypted, unbounded, in /var/log,
// where backups and log shippers reach and the mode does not follow.  What
// auditing actually needs is who ran what, when, against which refs, and to
// what effect, and none of that requires a value.  Confirming a credential
// arrived is what the redaction counts are for.
//
// The response carries a log_id that points into this file, so the agent can
// say "see log 2026-08-05T14:22:01Z-a91f" without being able to read it.
//
// One caveat, and it is the same one the response carries: a value refused at
// load is absent from the redactor, so if it reaches the output by some other
// route it arrives here in plaintext too.  Lengthen it; faramir-broker
// --check names every such ref.
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
	// OpenFile with an explicit mode rather than umask-plus-touch: the umask is
	// process-wide, and a child forked by another request during that window
	// would inherit it and create files the dev group cannot read.
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
	fh, err := os.OpenFile(l.config.LogPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// Never fail a request because logging broke.
		log.Printf("audit write failed: %v", err)
		return
	}
	defer fh.Close()
	if _, err := fh.Write(append(line, '\n')); err != nil {
		log.Printf("audit write failed: %v", err)
	}
}

// cutAtRune returns the first limit bytes of s, backing off only far enough
// not to end on a partial rune, which JSON would otherwise record as U+FFFD.
//
// The search is bounded to UTFMax because that is the longest a partial rune
// can be.  Scanning back for the first valid prefix instead would discard
// everything after the last invalid byte in the record: brokered output is raw
// PTY bytes, so a child printing binary or Latin-1 puts one mid-stream, and
// the record would silently lose the rest while still claiming a clean cut.
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

// Collector accumulates the redacted stream for one invocation, with a hard
// cap of its own: the log may hold more of a long run than the response does,
// but never anything the response would not have shown.
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
