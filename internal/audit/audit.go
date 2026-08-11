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
//  3. Every log_id is distinct.  It carries the writer's own nonce and a counter
//     that only advances, so two records repeat an id only if one process issued
//     16 million of them inside a second.
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
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
// two Logs in one process (a test, or `faramir rekey` opening its own) must not
// hand out the same id.
var (
	logIDs  atomic.Uint32
	logSeed = processNonce()
)

// processNonce separates one writer's ids from another's.  Every record on a
// host is normally the broker's, which is one process and so one counter; this
// is what keeps `faramir edit` and `faramir rekey`, which write their own, from
// starting at the same place in the same second.
func processNonce() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// NewLogID is a timestamp, this writer's nonce, and a counter that only
// advances.  Distinct by construction rather than by hoping two random bytes do
// not meet: at four concurrent commands a host reaches a thousand records a
// second, and sixteen bits of randomness collide at that rate within minutes.
func NewLogID() string {
	seq := logIDs.Add(1)
	return fmt.Sprintf("%s-%04x%06x",
		time.Now().UTC().Format("2006-01-02T15:04:05Z"), logSeed, seq&0xffffff)
}

// Output is a command's recorded output and how much of it was left out.  The
// count travels beside the text because whoever dropped the bytes is the only
// thing that knows how many there were: [Collector] drops them as the run
// streams, so nothing downstream can measure what it never held.
type Output struct {
	Text    string
	Dropped int
}

// Log is an append-only JSONL sink.  One record per brokered invocation.
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
	return max(l.config.MaxRecordBytes-len(skeleton)-1, minOutputBudget)
}

// open returns the log open for append, creating it 0600 if it is not there.
//
// Nothing is cached across calls.  A latch here made "can this be written?" a
// question answered once, at startup, about a host that had not run anything
// yet -- and every answer after that was about the past: a read-only remount, an
// immutable bit, an owner changed by a hand-edited logrotate rule, none of them
// seen, and Unwritable saying yes to all of them.  That is the state
// refuseUnauditable exists to rule out, so it is asked again every time, for the
// price of an open and a close.
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
	free := int64(fs.Bavail) * int64(fs.Bsize)
	if want := int64(l.config.MaxRecordBytes); free < want {
		return fmt.Sprintf("%s has %d bytes free and one record may need %d",
			filepath.Dir(l.config.LogPath), free, want)
	}
	return ""
}

// Write records one invocation together with its redacted output.
func (l *Log) Write(record map[string]any, output Output) {
	payload := make(map[string]any, len(record)+2)
	maps.Copy(payload, record)

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

// reductions are what encode falls back through when a record does not fit,
// each a ceiling on one string and on how many entries a list or a map keeps.
// Both are needed: a record can be too large because one field is long (argv
// holding a generated `--extra-vars` blob) or because there are many of them
// (an env_refs map naming the same value under a thousand names), and cutting
// only strings leaves the second case unreachable by any ceiling.
//
// Deliberately few, and each a long way below the last: this runs on a record
// that is already over the cap, and an operator reading one wants to know it was
// reduced, not to receive it exactly at the limit.
var reductions = [][2]int{{fieldCeiling, 64}, {256, 8}, {64, 4}}

// encode is one record as one line, never longer than the cap.  It reduces
// rather than gives up, because what is over the cap is almost always one
// caller-chosen field and the rest of the record is the part being audited.
func (l *Log) encode(payload map[string]any) []byte {
	limit := l.config.MaxRecordBytes
	line, err := json.Marshal(payload)
	if err == nil && len(line)+1 <= limit {
		return append(line, '\n')
	}
	if err != nil {
		log.Printf("audit marshal failed: %v", err)
	} else {
		before, _ := payload["output"].(string)
		for _, step := range reductions {
			// Each field, not the record.  reduce() bounds how many entries a
			// collection keeps, and applied to the payload itself that ceiling is a
			// ceiling on the record's own fields: it deleted them in reverse key
			// order until few enough were left, so `redactions` -- what says which
			// credentials the command used -- went first, and what landed looked like
			// an ordinary complete record.  The field set is the code's, not a
			// caller's, and is never what is too large.
			for key, value := range payload {
				payload[key] = reduce(value, step[0], step[1])
			}
			payload["record_reduced"] = true
			// The output field is reduced along with the rest, so what it says about
			// itself has to keep up: a record whose output was cut and does not say so
			// reads as a complete one.
			if after, _ := payload["output"].(string); len(after) < len(before) {
				payload["output_truncated"] = true
				dropped, _ := payload["output_dropped"].(int)
				payload["output_dropped"] = dropped + len(before) - len(after)
				before = after
			}
			if line, err = json.Marshal(payload); err == nil && len(line)+1 <= limit {
				return append(line, '\n')
			}
		}
	}
	return stubLine(payload)
}

// stubLine is the last reduction: a record cut back to the fact that it
// happened.  It is what makes encode total -- for any input there is a line, and
// it is under the cap -- and every caller is spared the question of what to do
// when there is not.
//
// Not dead code, though nothing a brokered command sends reaches it: what it
// guards is a record whose *field set* is too large, and the field set is the
// code's.  Add enough fields to a record and a small max_record_bytes reaches
// this, which is the day it earns its place.
func stubLine(payload map[string]any) []byte {
	const why = "this record did not fit [audit] max_record_bytes and was reduced to its identity"
	if line, err := json.Marshal(map[string]any{
		"log_id": payload["log_id"], "op": payload["op"], "peer": payload["peer"],
		"error": why, "record_reduced": true,
	}); err == nil {
		return append(line, '\n')
	}
	// A value that will not marshal at all is what brought us here, and the same
	// value is in the map above.  Every key and value below is a string, and
	// marshalling strings cannot fail, so this step has no failure of its own.
	// Without it the line was "\n", and a blank line is the one thing a reader
	// passes over in silence: the record would be gone with nothing to notice.
	line, _ := json.Marshal(map[string]string{
		"log_id": clamp(fmt.Sprint(payload["log_id"]), 256),
		"op":     clamp(fmt.Sprint(payload["op"]), 256),
		"peer":   clamp(fmt.Sprint(payload["peer"]), 256),
		"error":  why,
	})
	if len(line) == 0 {
		// Unreachable, and the belt to the braces: the invariant is that this
		// function returns a record, so it does not depend on being right about that.
		line = []byte(`{"error":"` + why + `"}`)
	}
	return append(line, '\n')
}

// reduce cuts every string in the record to strLimit encoded bytes and every list
// and map to items entries, saying so where it does.  It walks what a record is
// made of rather than naming fields, so a field added later is bounded without
// this having to hear about it.
//
// Encoded bytes, not raw ones: the cap this serves is counted in what the line
// spends, so a ceiling counted any other way is a ceiling in the wrong unit --
// two hundred arguments of a thousand '<' each are 200KB raw, under any
// per-string limit worth having, and 1.2MB once encoded.
func reduce(value any, strLimit, items int) any {
	switch typed := value.(type) {
	case string:
		return clamp(typed, strLimit)
	case map[string]any:
		for key, inner := range typed {
			typed[key] = reduce(inner, strLimit, items)
		}
		return dropEntries(typed, items)
	case map[string]string:
		for key, inner := range typed {
			typed[key] = clamp(inner, strLimit)
		}
		return dropEntries(typed, items)
	case []string:
		for i, inner := range typed {
			typed[i] = clamp(inner, strLimit)
		}
		if len(typed) > items {
			return append(typed[:items:items], more(len(typed)-items))
		}
	case []any:
		for i, inner := range typed {
			typed[i] = reduce(inner, strLimit, items)
		}
		if len(typed) > items {
			return append(typed[:items:items], any(more(len(typed)-items)))
		}
	default:
		return reduceTyped(value, strLimit, items)
	}
	return value
}

// reduceTyped bounds a slice whose element type this package cannot name.
// `redactions` is []redact.Count, and naming it here would make the audit log
// depend on the redactor to know how large it may be; more to the point, the
// next such field would need the same edit, and the promise above is that it
// would not.  Reflection is the price of that promise, and it is paid only on a
// record already over the cap.
//
// The result is []any, so the marker can sit in it: a list of objects that ends
// in a sentence is odd to look at and says what happened, which a list silently
// missing 19,000 entries does not.
func reduceTyped(value any, strLimit, items int) any {
	if value == nil {
		return value
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice || rv.Len() <= items {
		return value
	}
	out := make([]any, 0, items+1)
	for i := range items {
		out = append(out, reduce(rv.Index(i).Interface(), strLimit, items))
	}
	return append(out, any(more(rv.Len()-items)))
}

// clamp is one string at an encoded ceiling, marked where it was cut.
func clamp(text string, budget int) string {
	if encodedLen(text) <= budget {
		return text
	}
	return prefixWithin(text, max(budget-markerReserve, 1)) + "… (cut to fit the record)"
}

func more(n int) string { return fmt.Sprintf("… (%d more, cut to fit the record)", n) }

// dropEntries keeps the first items keys in sorted order, so which entries
// survive is the same on every run rather than whatever the map iterated to
// first.  A map is generic over its value type, so this is written twice rather
// than reached through reflection.
func dropEntries[V any](entries map[string]V, items int) map[string]V {
	if len(entries) <= items {
		return entries
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys[items:] {
		delete(entries, key)
	}
	return entries
}

// Excerpt keeps the head and the tail of a command's output and says what it
// left out, measured in the bytes the record will spend rather than the bytes
// the command wrote.
//
// Head and tail rather than a prefix: what an operator wants from a long run is
// how it started and how it ended, and a prefix is the half that is never the
// answer.
func Excerpt(output string, budget int) (text string, dropped int) {
	if encodedLen(output) <= budget {
		return output, 0
	}
	half := max((budget-markerReserve)/2, 1)
	head := prefixWithin(output, half)
	tail := suffixWithin(output, half)
	if len(head)+len(tail) >= len(output) {
		return output, 0
	}
	dropped = len(output) - len(head) - len(tail)
	return head + marker(dropped) + tail, dropped
}

func marker(dropped int) string {
	return fmt.Sprintf("\n[faramir: %d bytes of output dropped; [audit] "+
		"max_record_bytes is what a record keeps]\n", dropped)
}

// encodedLen is what json.Marshal will spend on s inside a string, which is what
// the cap is counted in.  Six bytes for a byte a command picked, one for most of
// what it prints.
func encodedLen(s string) int {
	total := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		total += encodedRuneLen(r, size)
		i += size
	}
	return total
}

func encodedRuneLen(r rune, size int) int {
	switch {
	case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t':
		return 2
	case r < 0x20:
		return 6
	// HTML escaping is on for json.Marshal, so these three cost six apiece, which
	// is what makes a page of XML the cheapest way to write a very long line.
	case r == '<' || r == '>' || r == '&':
		return 6
	// An invalid byte is recorded as the escape \ufffd rather than as the three
	// bytes that rune encodes to, so it costs six like the rest of them.
	case r == utf8.RuneError && size == 1:
		return 6
	// Escaped by encoding/json whatever the settings are, for JSONP's sake.
	case r == '\u2028' || r == '\u2029':
		return 6
	}
	return size
}

// prefixWithin is the longest prefix of s whose encoded length fits in budget,
// ending on a rune boundary.
func prefixWithin(s string, budget int) string {
	spent := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		cost := encodedRuneLen(r, size)
		if spent+cost > budget {
			return s[:i]
		}
		spent += cost
		i += size
	}
	return s
}

// suffixWithin is prefixWithin from the other end.
func suffixWithin(s string, budget int) string {
	spent := 0
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		cost := encodedRuneLen(r, size)
		if spent+cost > budget {
			return s[i:]
		}
		spent += cost
		i -= size
	}
	return s
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

// Collector accumulates the redacted stream for one invocation, keeping the head
// and the tail and counting what it drops between them.
//
// Bounded as it goes rather than at the end: a run that prints for an hour is
// held in the broker's memory while it does, and the record is the same size
// whether the command wrote a kilobyte or a gigabyte.
type Collector struct {
	budget  int
	head    strings.Builder
	headLen int // encoded, so the budget means the same here as in the record
	// headShut is set by the first chunk that goes to the tail.  Without it the
	// head keeps taking whatever still fits, so a chunk too large for the room
	// left goes to the tail and a smaller one after it lands in the head, ahead of
	// it: the record then shows a run's own output out of the order it was
	// written, which is worse than showing less of it.
	headShut bool
	tail     []string
	tailLen  int
	dropped  int
}

func NewCollector(budget int) *Collector {
	return &Collector{budget: max(budget, minOutputBudget)}
}

func (c *Collector) half() int { return max((c.budget-markerReserve)/2, 1) }

func (c *Collector) Add(text string) {
	if text == "" {
		return
	}
	// Fill the head first, then treat everything after it as tail, dropping from
	// the front of the tail as it overflows.  A ring of chunks rather than of
	// bytes: chunks arrive small, and the one that overshoots is trimmed once.
	if !c.headShut && c.headLen < c.half() {
		keep := prefixWithin(text, c.half()-c.headLen)
		if keep != "" {
			c.head.WriteString(keep)
			c.headLen += encodedLen(keep)
			text = text[len(keep):]
		}
		if text == "" {
			return
		}
	}
	// Whatever did not fit the head ends it: from here the record is written in
	// the order the run wrote it, or it is not worth reading.
	c.headShut = true
	c.tail = append(c.tail, text)
	c.tailLen += encodedLen(text)
	for c.tailLen > c.half() && len(c.tail) > 1 {
		c.dropped += len(c.tail[0])
		c.tailLen -= encodedLen(c.tail[0])
		c.tail = c.tail[1:]
	}
	// One chunk longer than the whole tail budget: keep its own tail.
	if c.tailLen > c.half() {
		keep := suffixWithin(c.tail[0], c.half())
		c.dropped += len(c.tail[0]) - len(keep)
		c.tail[0] = keep
		c.tailLen = encodedLen(keep)
	}
}

// Output is what was kept and how much was not.
func (c *Collector) Output() Output {
	head, tail := c.head.String(), strings.Join(c.tail, "")
	if c.dropped == 0 {
		return Output{Text: head + tail}
	}
	return Output{Text: head + marker(c.dropped) + tail, Dropped: c.dropped}
}
