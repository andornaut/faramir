package server

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
)

// serving starts the broker on its socket and returns a dialer for it.
func serving(t *testing.T, s *Server) func() (net.Conn, *sockutil.LineReader) {
	t.Helper()
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	return func() (net.Conn, *sockutil.LineReader) {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn, sockutil.NewLineReader(conn, 1<<26)
	}
}

// chunk sends one redact chunk and returns what came back.
func chunk(t *testing.T, conn net.Conn, lines *sockutil.LineReader, text string, more bool) string {
	t.Helper()
	request := map[string]any{"op": "redact", "text": text}
	if more {
		request["more"] = true
	}
	if err := sockutil.Send(conn, request); err != nil {
		t.Fatal(err)
	}
	line, err := lines.Next()
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Output string `json:"output"`
		Error  *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("malformed response %q: %v", line, err)
	}
	if response.Error != nil {
		t.Fatalf("chunk refused: %s", response.Error.Code)
	}
	return response.Output
}

// The bug this shape exists for: a value split between two chunks.
//
// The client has to break a line longer than one chunk somewhere, and before
// the broker kept a redactor for the connection that break landed between two
// requests with a redactor each. Neither half held the whole value, so neither
// matched it, and the value went out in the clear with exit status 0.
func TestAValueSplitBetweenTwoChunksIsRedacted(t *testing.T) {
	const value = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"db/password": value})
	dial := serving(t, s)
	conn, lines := dial()

	// The split falls inside the value, which is the only interesting place.
	head, tail := value[:9], value[9:]
	got := chunk(t, conn, lines, "before "+head, true)
	got += chunk(t, conn, lines, tail+" after", false)

	if strings.Contains(got, value) {
		t.Errorf("the value crossed the chunk break in the clear: %q", got)
	}
	if !strings.Contains(got, "«SECRET:db/password»") {
		t.Errorf("no token in %q", got)
	}
	if !strings.HasPrefix(got, "before ") || !strings.HasSuffix(got, " after") {
		t.Errorf("the text around it was not preserved: %q", got)
	}
}

// Whatever the client's chunking, the bytes come back whole and in order.
func TestAStreamReassemblesToTheWholeInput(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	dial := serving(t, s)
	conn, lines := dial()

	pieces := []string{"alpha ", "bravo ", "charlie ", "delta"}
	var out strings.Builder
	for i, piece := range pieces {
		out.WriteString(chunk(t, conn, lines, piece, i < len(pieces)-1))
	}
	if got, want := out.String(), strings.Join(pieces, ""); got != want {
		t.Errorf("stream reassembled to %q, want %q", got, want)
	}
}

// The last chunk is what releases the tail the redactor held back, so a stream
// that ends must not lose its final bytes.
func TestTheLastChunkFlushesWhatWasHeldBack(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	dial := serving(t, s)
	conn, lines := dial()

	// A tail shorter than the overlap is entirely held back by the first chunk.
	got := chunk(t, conn, lines, "keep this", true)
	got += chunk(t, conn, lines, "", false)
	if got != "keep this" {
		t.Errorf("stream produced %q, want %q: an empty last chunk still flushes", got, "keep this")
	}
}

// One request that stands alone is unchanged: it flushes, because nothing said
// another chunk was coming.
func TestASingleRequestStillFlushes(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	dial := serving(t, s)
	conn, lines := dial()

	if got := chunk(t, conn, lines, "a hunter2-correct-horse b", false); got != "a «SECRET:db/password» b" {
		t.Errorf("one-shot redact returned %q", got)
	}
}

// Handle has nowhere to keep a redactor, so a chunked request there would feed
// text and never flush the tail.  Refused rather than quietly completed.
func TestAChunkedRequestWithNoConnectionIsRefused(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	got := s.Handle(map[string]any{"op": "redact", "text": "x", "more": true}, &sockutil.Peer{UID: 1000})
	failure, ok := got["error"].(map[string]string)
	if !ok {
		t.Fatalf("a chunked request outside a stream was answered: %v", got)
	}
	if failure["code"] != "bad_request" {
		t.Errorf("error code %q, want bad_request", failure["code"])
	}
}

// A malformed redact request is refused rather than answered with whatever the
// missing or mistyped field defaults to: an accepted request returns text the
// caller then treats as redacted.
func TestAMalformedRedactRequestIsRefused(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	for _, tc := range []struct {
		name    string
		request map[string]any
	}{
		{"no text at all", map[string]any{"op": "redact"}},
		{"text that is not a string", map[string]any{"op": "redact", "text": 42}},
		{"more as a string", map[string]any{"op": "redact", "text": "x", "more": "yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.Handle(tc.request, &sockutil.Peer{UID: 1000}); got["error"] == nil {
				t.Errorf("accepted: %v", got)
			}
		})
	}
}

// One stream is one thing that happened, so it writes one record carrying the
// whole of it, rather than one per chunk.
func TestAStreamWritesOneAuditRecord(t *testing.T) {
	const value = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"db/password": value})
	dial := serving(t, s)
	conn, lines := dial()

	chunk(t, conn, lines, "one "+value+" ", true)
	chunk(t, conn, lines, "two "+value+" ", true)
	chunk(t, conn, lines, "three", false)

	records := auditRecords(t, s, 1)
	if len(records) != 1 {
		t.Fatalf("wrote %d audit records for one stream, want 1", len(records))
	}
	record := records[0]
	if record["op"] != "redact" {
		t.Errorf("op = %v", record["op"])
	}
	// The totals are the stream's, not the last chunk's.
	got, ok := record["input_bytes"].(float64)
	if !ok {
		t.Fatalf("input_bytes = %#v, want a number", record["input_bytes"])
	}
	if int(got) != len("one "+value+" ")+
		len("two "+value+" ")+len("three") {
		t.Errorf("input_bytes = %v, want the whole stream", got)
	}
	body, err := json.Marshal(record["redactions"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"count":2`) {
		t.Errorf("redactions = %s, want both occurrences counted once for the stream", body)
	}
	if strings.Contains(string(body), value) {
		t.Error("the audit record carries the value")
	}
}

// A peer that goes away mid-stream still leaves a record of what was redacted
// before it did.
func TestAnAbandonedStreamIsStillAudited(t *testing.T) {
	const value = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"db/password": value})
	dial := serving(t, s)
	conn, lines := dial()

	chunk(t, conn, lines, "one "+value+" and more to come", true)
	_ = conn.Close()

	if records := auditRecords(t, s, 1); len(records) != 1 {
		t.Fatalf("an abandoned stream wrote %d records, want 1", len(records))
	}
}

// auditRecords reads the audit log, waiting briefly for at least want records:
// the one a stream writes when it ends lands as the connection is torn down.
func auditRecords(t *testing.T, s *Server, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var records []map[string]any
		body, err := os.ReadFile(s.Config.Audit.LogPath)
		if err == nil {
			for line := range strings.SplitSeq(strings.TrimSpace(string(body)), "\n") {
				if line == "" {
					continue
				}
				var record map[string]any
				if json.Unmarshal([]byte(line), &record) == nil {
					records = append(records, record)
				}
			}
		}
		if len(records) >= want || time.Now().After(deadline) {
			return records
		}
		time.Sleep(20 * time.Millisecond)
	}
}
