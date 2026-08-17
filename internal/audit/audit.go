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
//
// # What this package guarantees
//
// Every field of a record is chosen by the account the log exists to hold to
// account, so the guarantees are made here, where the record is built, rather
// than asked of whatever reads it later:
//
//  1. One record is one line, and no line exceeds [config.AuditConfig].
//     MaxRecordBytes.  The cap is counted in the bytes the line actually spends,
//     escapes included, because '<', '>', '&' and every C0 control cost six once
//     encoded: a cap counted before encoding is a cap the command chooses the
//     meaning of.  So a reader needs no ceiling of its own, and cannot be shown a
//     record it must refuse.
//  2. An append is exclusive and all-or-nothing.  Every writer takes an
//     advisory lock, and a write that lands short is taken back, so no line is
//     ever left open.  This matters because the next record appends onto an open
//     line: without it one failed write costs two records, and the second of them
//     is one that succeeded.
//  3. Every log_id is distinct.  It carries the second it was minted in, the
//     writer's own nonce and a counter that only advances, so two records repeat
//     an id only if one process issued 16 million of them inside a second,
//     having drawn the same nonce as whatever else was writing.
//
// None of the three depends on how much a command wrote, how many ran at once,
// or how full the disk is.
package audit

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/config"
)

// Bounds on what one record may carry.  Only MaxRecordBytes is configurable:
// the rest are the arithmetic that makes it hold whatever a caller passes.
const (
	// recordReserve is what is held back from the record's budget for everything
	// that is not the command's output: the argv, the cwd, the refs, the error,
	// the redaction counts and the keys around them.  Generous on purpose, the
	// output budget being the part worth tuning and the rest nobody's problem.
	recordReserve = 32 * 1024

	// fieldCeiling is what every string in a record is cut to when the line comes
	// out over the cap anyway.  One rule for all of them rather than a limit per
	// field: argv is the agent's, and execve will take two megabytes of it.
	fieldCeiling = 4 * 1024

	// minOutputBudget keeps a record with a small MaxRecordBytes from having no
	// output field at all.
	minOutputBudget = 2 * 1024

	// markerReserve is room for the line that says what was left out.
	markerReserve = 128
)

// logIDs is the counter half of a log_id.  Package-level rather than per-Log:
// two Logs in one process (a test, or `faramir sops rekey` opening its own) must not
// hand out the same id.
var (
	logIDs  atomic.Uint32
	logSeed = processNonce()
)

// processNonce separates one writer's ids from another's.  Every record on a
// host is normally the broker's, which is one process and so one counter; this
// is what keeps `faramir sops edit` and `faramir sops rekey`, which write their own, from
// starting at the same place in the same second.
func processNonce() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// idAlphabet is base36, digits then lowercase letters.  An id is read off one
// terminal and typed into another, so it spends its characters on what a
// keyboard makes easy.
const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// idClockChars is what the clock half of an id costs, and so how long it is
// before one repeats: 36^4 seconds is 19.4 days.  Bounded by what has to be
// distinct rather than by what a person might read, which is why it is four
// characters and not a timestamp: `faramir logs` reads only the live log, and
// logrotate turns that over weekly.
const idClockChars = 4

// idClockCycle is 36^idClockChars.
const idClockCycle = 36 * 36 * 36 * 36

// NewLogID is the clock, this writer's nonce, and a counter that only advances.
// Distinct by construction rather than by hoping random bytes do not meet: two
// ids collide only when a process mints them in the same second, having drawn
// the same nonce as another, more than 16 million apart in its own counter.
//
// It carries no readable time.  Every record says when it happened in a field
// of its own (started_at, or the at Write stamps), so an id spends nothing on
// what a reader has already been told.
func NewLogID() string {
	seq := logIDs.Add(1)
	clock := make([]byte, idClockChars)
	secs := uint64(time.Now().UTC().Unix()) % idClockCycle
	for i := idClockChars - 1; i >= 0; i-- {
		clock[i] = idAlphabet[secs%36]
		secs /= 36
	}
	return fmt.Sprintf("%s%04x%06x", clock, logSeed, seq&0xffffff)
}

// Output is a command's recorded output and how much of it was left out.  The
// count travels beside the text because whoever dropped the bytes is the only
// thing that knows how many there were: [Collector] drops them as the run
// streams, so nothing downstream can measure what it never held.
type Output struct {
	Text    string
	Dropped int
}

// Log is an append-only JSONL sink.  One record per brokered invocation, except
// an exec, which writes a pair sharing one log_id: one when the child starts and
// one when it ends.
type Log struct {
	config config.AuditConfig
	mu     sync.Mutex
}

func NewLog(cfg config.AuditConfig) *Log { return &Log{config: cfg} }

// OutputBudget is how many bytes of a record's line the command's output may
// occupy, once escaped.  Derived rather than configured: an operator sets how
// large a record may be, and the rest of the record is not theirs to size.
//
// What [Collector] streams against, so it is the constant-reserve estimate: the
// rest of the record does not exist yet while a run is still producing output.
// Write sizes the same field again against the record it ends up with.
func (l *Log) OutputBudget() int {
	return max(l.config.MaxRecordBytes-recordReserve, minOutputBudget)
}

// roomForOutput is what is left of the cap once everything else in the record is
// counted: the record is marshalled with an empty output field and measured.
// One extra pass over a small map, and it is what keeps an ordinary command with
// a long argv from being recorded as a reduced one.
func (l *Log) roomForOutput(payload map[string]any) int {
	rest := make(map[string]any, len(payload)+3)
	maps.Copy(rest, payload)
	rest["output"] = ""
	// The fields Write adds after this measurement, so the room accounts for them
	// rather than being spent and then overrun by a few dozen bytes.
	rest["output_dropped"] = 0
	rest["output_truncated"] = true
	rest["record_reduced"] = true
	skeleton, err := json.Marshal(rest)
	if err != nil {
		return l.OutputBudget()
	}
	// One for the newline the line carries.
	room := l.config.MaxRecordBytes - len(skeleton) - 1
	if len(skeleton) >= l.config.MaxRecordBytes {
		// The rest of the record is over the cap on its own, so reduction is about to
		// cut it down and the output that survives has room after that.  Sizing the
		// output to nothing here would throw it away because the argv was long, which
		// is the wrong one of the two to lose.
		return l.OutputBudget()
	}
	// No floor under what is left: a floor is a claim about room that is not
	// there, and the record then overshoots and is reduced, so the output it was
	// protecting comes out smaller than the honest arithmetic would have left it.
	return max(room, 0)
}

// open returns the log open for append, creating it 0600 if it is not there.
//
// Nothing is cached across calls.  A cached answer is a claim about the host as
// it was when the answer was taken, and what makes the log unwritable happens
// after that: a read-only remount, an immutable bit, an owner changed by a
// hand-edited logrotate rule.  A latch would report none of them, and would have
// Unwritable saying yes to all of them, which is the state refuseUnauditable
// exists to rule out.  So it is asked again every time, for the price of an open
// and a close.
//
// O_CREATE though the file usually exists: logrotate renames it away, and the
// next record makes the new one rather than waiting for anything to notice.
func (l *Log) open() (*os.File, error) {
	path := l.config.LogPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// An explicit mode rather than umask-plus-touch: the umask is process-wide,
	// and a child forked during that window would inherit it.
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := fh.Chmod(0o600); err != nil {
		_ = fh.Close()
		return nil, err
	}
	return fh, nil
}

// Unwritable reports why the next record could not be written, or "" when one
// can be.  Asked before a command runs rather than after: a command that cannot
// be recorded is refused, so "it ran and nothing says so" is not a state this
// host reaches.  See Server.refuseUnauditable.
//
// Room for one whole record, not for one byte: a filesystem with less than that
// left is one where the next write lands short, and the point is to answer
// before that rather than to survive it.
func (l *Log) Unwritable() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	fh, err := l.open()
	if err != nil {
		return fmt.Sprintf("%s cannot be opened for append (%v)", l.config.LogPath, err)
	}
	_ = fh.Close()
	var fs unix.Statfs_t
	if err := unix.Statfs(filepath.Dir(l.config.LogPath), &fs); err != nil {
		// Not a refusal: a filesystem that will not answer is not one that has been
		// shown to be full, and refusing every command over a failed statfs would
		// take the host down for a question nobody asked.
		log.Printf("cannot measure free space under %s: %v", l.config.LogPath, err)
		return ""
	}
	// Bavail is unsigned and Bsize is not, which is why only one is converted.
	free := int64(fs.Bavail) * fs.Bsize
	if want := int64(l.config.MaxRecordBytes); free < want {
		return fmt.Sprintf("%s has %d bytes free and one record may need %d",
			filepath.Dir(l.config.LogPath), free, want)
	}
	return ""
}

// Write records one invocation together with its redacted output.
func (l *Log) Write(record map[string]any, output Output) {
	payload := make(map[string]any, len(record)+3)
	maps.Copy(payload, record)

	// When, in a field, so no reader has to take it from the id.  Only where the
	// record does not already say: an exec carries started_at, which is when its
	// child ran rather than when this line was written, and the two differ by the
	// whole length of the command.  Named apart for that reason: a redact stream
	// or an approval is recorded once it is over, and calling that a start would
	// be untrue.
	if _, ok := payload["started_at"]; !ok {
		payload["at"] = time.Now().UTC().Unix()
	}

	// Sized against what the rest of the record actually costs, rather than
	// against the constant Collector had to guess with while the run was still
	// streaming.  argv is the caller's too and can be most of a record on its own,
	// so a reserve fixed in advance is either too small, and an ordinary command
	// needs reducing, or too large, and a short run's output is cut to leave room
	// nothing used.
	//
	// Collector has usually excerpted this already; what is left here is the
	// difference between its guess and the answer, plus the case of a caller
	// handing over a string of its own.
	text, dropped := Excerpt(output.Text, l.roomForOutput(payload))
	payload["output"] = text
	if total := output.Dropped + dropped; total > 0 {
		payload["output_dropped"] = total
		payload["output_truncated"] = true
	}

	line := l.encode(payload)

	l.mu.Lock()
	defer l.mu.Unlock()
	// Opened per write rather than held, which is what makes a plain rename safe
	// with no copytruncate and no signal.
	fh, err := l.open()
	if err != nil {
		// Logging that broke does not fail a request here; the request was refused
		// before it ran, by Unwritable, or it was not one that runs anything.
		log.Printf("audit write failed: %v", err)
		return
	}
	defer func() { _ = fh.Close() }()
	appendLine(fh, line, l.config.LogPath)
}

// appendLine writes one line under an exclusive lock, and takes back a write
// that landed short.
//
// The lock is what makes the truncate safe: it is held by every writer, so the
// end of the file during the write is this record's own end and nothing else's.
// A host does not need lock-free concurrent appends -- four brokered commands at
// once is the configured ceiling, and `edit` and `rekey` are somebody typing --
// so paying a lock to make the file always well formed is the cheap side of the
// trade.
func appendLine(fh *os.File, line []byte, path string) {
	if err := unix.Flock(int(fh.Fd()), unix.LOCK_EX); err != nil {
		log.Printf("audit write failed: cannot lock %s: %v", path, err)
		return
	}
	// Released by the close in Write; naming it here says the window on purpose.
	defer func() { _ = unix.Flock(int(fh.Fd()), unix.LOCK_UN) }()

	end, err := fh.Seek(0, io.SeekEnd)
	if err != nil {
		log.Printf("audit write failed: cannot measure %s: %v", path, err)
		return
	}
	written, err := fh.Write(line)
	if err == nil {
		return
	}
	log.Printf("audit write failed: %v", err)
	if written <= 0 {
		return
	}
	// What landed is a line with no end on it, and the next record would append
	// onto it, so one failure would cost this record and the next.  Truncating
	// back costs this one alone, and leaves a file every reader can still parse.
	if err := fh.Truncate(end); err != nil {
		log.Printf("audit could not take back a short write, so the next record "+
			"appends to a torn line and neither reads back: %v", err)
	}
}
