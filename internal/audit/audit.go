// Package audit writes the audit log, readable only by the broker's uid.
//
// It holds no secret value: output is recorded after redaction, the refs are
// names, and nothing is ever substituted into argv. The response carries a
// log_id pointing into this file, so the agent can cite a record it cannot
// read. One caveat: a value refused at load is absent from the redactor, so if
// it reaches the output it arrives here in plaintext too, and `faramir broker
// --check` names every such ref.
//
// # What this package guarantees
//
// Every field of a record is chosen by the account the log exists to hold to
// account, so the guarantees are made here rather than asked of whatever reads
// the file later:
//
//  1. One record is one line, and no line exceeds config.MaxRecordBytes. The
//     cap counts the bytes the line spends, escapes included, so a reader needs
//     no ceiling of its own.
//  2. An append is exclusive and all-or-nothing. Every writer takes an
//     advisory lock, and a write that lands short is taken back, so no line is
//     left open for the next record to append onto.
//  3. Every log_id is distinct. It carries the second it was minted in, the
//     writer's own nonce and a counter that only advances.
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

// Bounds on what one record may carry: the arithmetic that makes
// config.MaxRecordBytes hold whatever a caller passes.
const (
	// recordReserve is what is held back from the record's budget for everything
	// that is not the command's output: the argv, the cwd, the refs, the error,
	// the redaction counts and the keys around them.
	recordReserve = 32 * 1024

	// fieldCeiling is what every string in a record is cut to when the line comes
	// out over the cap anyway. One rule for all of them: argv is the agent's,
	// and execve will take two megabytes of it.
	fieldCeiling = 4 * 1024

	// minOutputBudget keeps a record with a small MaxRecordBytes from having no
	// output field at all.
	minOutputBudget = 2 * 1024

	// markerReserve is room for the line that says what was left out.
	markerReserve = 128
)

// logIDs is the counter half of a log_id. Package-level rather than per-Log:
// two Logs in one process must not hand out the same id.
var (
	logIDs  atomic.Uint32
	logSeed = processNonce()
)

// processNonce separates one writer's ids from another's: `faramir vault edit`
// and `faramir reader reseal` write their own records, and would otherwise
// start at the same place in the same second as the broker.
func processNonce() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// idAlphabet is base36, digits then lowercase letters: an id is read off one
// terminal and typed into another.
const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// idClockChars is what the clock half of an id costs, and so how long it is
// before one repeats: 36^4 seconds is 19.4 days. Four characters rather than a
// timestamp: `faramir logs` reads only the live log, which logrotate turns over
// weekly.
const idClockChars = 4

// idClockCycle is 36^idClockChars.
const idClockCycle = 36 * 36 * 36 * 36

// NewLogID is the clock, this writer's nonce, and a counter that only advances,
// so two ids collide only when a process mints them in the same second, having
// drawn the same nonce as another, more than 16 million apart in its own
// counter. It carries no readable time: every record says when it happened in
// started_at or the `at` Write stamps.
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

// Output is a command's recorded output and how much of it was left out. The
// count travels beside the text because [Collector] drops the bytes as the run
// streams, so nothing downstream can measure what it never held.
type Output struct {
	Text    string
	Dropped int
}

// Log is an append-only JSONL sink. One record per brokered invocation, except
// an exec, which writes a pair sharing one log_id: one when the child starts and
// one when it ends.
type Log struct {
	config config.AuditConfig
	mu     sync.Mutex
}

func NewLog(cfg config.AuditConfig) *Log { return &Log{config: cfg} }

// OutputBudget is how many bytes of a record's line the command's output may
// occupy, once escaped. What [Collector] streams against, so it is the
// constant-reserve estimate: the rest of the record does not exist yet while a
// run is still producing output. Write sizes the same field again against the
// record it ends up with.
func (l *Log) OutputBudget() int {
	return max(config.MaxRecordBytes-recordReserve, minOutputBudget)
}

// roomForOutput is what is left of the cap once everything else in the record
// is counted, by marshalling it with an empty output field and measuring. It
// is what keeps an ordinary command with a long argv from being recorded as a
// reduced one.
func (l *Log) roomForOutput(payload map[string]any) int {
	rest := make(map[string]any, len(payload)+3)
	maps.Copy(rest, payload)
	rest["output"] = ""
	// The fields Write adds after this measurement, so the room accounts for
	// them.
	rest["output_dropped"] = 0
	rest["output_truncated"] = true
	rest["record_reduced"] = true
	skeleton, err := json.Marshal(rest)
	if err != nil {
		return l.OutputBudget()
	}
	// One for the newline the line carries.
	room := config.MaxRecordBytes - len(skeleton) - 1
	if len(skeleton) >= config.MaxRecordBytes {
		// The rest of the record is over the cap on its own, so reduction is about
		// to cut it down and the output has room after that. Sizing the output to
		// nothing here would throw it away because the argv was long.
		return l.OutputBudget()
	}
	// No floor under what is left: a floor would claim room that is not there, and
	// the record would then overshoot and be reduced, leaving less output than the
	// honest arithmetic would have.
	return max(room, 0)
}

// open returns the log open for append, creating it 0600 if it is not there.
//
// Nothing is cached across calls: what makes the log unwritable happens after
// any cached answer was taken -- a read-only remount, an immutable bit, an owner
// changed by a hand-edited logrotate rule -- and Unwritable would then say yes
// to all of them. The price is an open and a close per record.
//
// O_CREATE though the file usually exists: logrotate renames it away, and the
// next record makes the new one.
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
// can be. Asked before a command runs: one that cannot be recorded is refused,
// so "it ran and nothing says so" is not a state this host reaches. See
// Server.refuseUnauditable.
//
// Room for one whole record, not for one byte: a filesystem with less than that
// left is one where the next write lands short.
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
		// Not a refusal: a filesystem that will not answer has not been shown to be
		// full, and refusing every command over a failed statfs would take the host
		// down.
		log.Printf("cannot measure free space under %s: %v", l.config.LogPath, err)
		return ""
	}
	// Bavail is unsigned and Bsize is not, which is why only one is converted.
	free := int64(fs.Bavail) * fs.Bsize
	if want := int64(config.MaxRecordBytes); free < want {
		return fmt.Sprintf("%s has %d bytes free and one record may need %d",
			filepath.Dir(l.config.LogPath), free, want)
	}
	return ""
}

// Write records one invocation together with its redacted output.
func (l *Log) Write(record map[string]any, output Output) {
	payload := make(map[string]any, len(record)+3)
	maps.Copy(payload, record)

	// When, in a field, so no reader has to take it from the id. Only where the
	// record does not already say: an exec carries started_at, which is when its
	// child ran rather than when this line was written, and the two differ by the
	// length of the command.
	if _, ok := payload["started_at"]; !ok {
		payload["at"] = time.Now().UTC().Unix()
	}

	// Sized against what the rest of the record actually costs, rather than
	// against the constant Collector had to guess with while the run was
	// streaming: argv is the caller's and can be most of a record on its own.
	// Collector has usually excerpted this already.
	text, dropped := excerpt(output.Text, l.roomForOutput(payload))
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
		// Logging that broke does not fail a request here: it was refused before it
		// ran, by Unwritable, or it runs nothing.
		log.Printf("audit write failed: %v", err)
		return
	}
	defer func() { _ = fh.Close() }()
	appendLine(fh, line, l.config.LogPath)
}

// appendLine writes one line under an exclusive lock, and takes back a write
// that landed short. The lock is what makes the truncate safe: every writer
// takes it, so the end of the file during the write is this record's own end.
func appendLine(fh *os.File, line []byte, path string) {
	if err := unix.Flock(int(fh.Fd()), unix.LOCK_EX); err != nil {
		log.Printf("audit write failed: cannot lock %s: %v", path, err)
		return
	}
	// Released by the close in Write; unlocked here to name the window.
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
	// onto it, so one failure would cost two records. Truncating back costs this
	// one alone.
	if err := fh.Truncate(end); err != nil {
		log.Printf("audit could not take back a short write, so the next record "+
			"appends to a torn line and neither reads back: %v", err)
	}
}
