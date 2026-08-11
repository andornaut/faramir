package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/andornaut/faramir/internal/sockutil"
)

// stubBroker answers the redact op by echoing the text back, and records what
// it was sent.  It carries a stream the way the real broker does: a chunk
// marked "more" keeps the connection open for the next one, and the chunk
// without it ends the stream.
type stubBroker struct {
	path string

	mu       sync.Mutex
	sizes    []int
	more     []bool
	conns    int
	chunks   int
	dieAfter int // drop the connection unanswered at this chunk; 0 never
}

func newStubBroker(t *testing.T) *stubBroker {
	t.Helper()
	b := &stubBroker{path: filepath.Join(t.TempDir(), "b.sock")}
	listener, err := net.Listen("unix", b.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); os.Remove(b.path) })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns++
			b.mu.Unlock()
			go b.serve(conn)
		}
	}()
	return b
}

func (b *stubBroker) serve(conn net.Conn) {
	defer conn.Close()
	lines := sockutil.NewLineReader(conn, 1<<26)
	for {
		line, err := lines.Next()
		if err != nil || len(line) == 0 {
			return
		}
		var request struct {
			Text string `json:"text"`
			More bool   `json:"more"`
		}
		if err := json.Unmarshal(line, &request); err != nil {
			return
		}
		b.mu.Lock()
		b.sizes = append(b.sizes, len(request.Text))
		b.more = append(b.more, request.More)
		b.chunks++
		die := b.dieAfter > 0 && b.chunks >= b.dieAfter
		b.mu.Unlock()
		if die {
			return // gone without answering, which is what a restart looks like
		}
		_ = sockutil.Send(conn, map[string]any{"output": request.Text})
		if !request.More {
			return
		}
	}
}

func (b *stubBroker) Sizes() []int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]int(nil), b.sizes...)
}

func (b *stubBroker) More() []bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]bool(nil), b.more...)
}

func (b *stubBroker) Conns() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns
}

// The broker's limit is on the encoded line, and chunkBytes is chosen so a
// chunk cannot exceed it however badly it encodes.  A partial buffer plus a
// full ReadSlice would put nearly twice that on the wire, and an oversized
// request comes back as too_large, which passes the text through unredacted.
func TestNoChunkExceedsTheChunkSize(t *testing.T) {
	broker := newStubBroker(t)

	// Short lines, so the buffer is nearly always partial when the next
	// ReadSlice lands.
	input := strings.Repeat(strings.Repeat("x", 60)+"\n", 4000)

	var out bytes.Buffer
	if err := redactStream(broker.path, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != input {
		t.Fatalf("output differs from input: %d bytes in, %d out", len(input), out.Len())
	}
	requests := broker.Sizes()
	if len(requests) < 2 {
		t.Fatalf("expected the input to be split, got %d request(s)", len(requests))
	}
	for i, size := range requests {
		if size > chunkBytes {
			t.Errorf("chunk %d carried %d bytes of text, over the %d-byte budget",
				i, size, chunkBytes)
		}
	}
}

// A long line arrives in pieces, each its own chunk.
func TestALineLongerThanTheBufferIsStillSplit(t *testing.T) {
	broker := newStubBroker(t)

	input := strings.Repeat("y", 5*chunkBytes) + "\n"
	var out bytes.Buffer
	if err := redactStream(broker.path, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != input {
		t.Fatalf("output differs: %d bytes in, %d out", len(input), out.Len())
	}
	for i, size := range broker.Sizes() {
		if size > chunkBytes {
			t.Errorf("chunk %d carried %d bytes of text, over the %d-byte budget",
				i, size, chunkBytes)
		}
	}
}

// Every chunk of one stream goes down one connection, and every chunk but the
// last says another follows.
//
// This is what puts the broker's redactor across the joins: it holds back a
// tail longer than the longest variant, so a value split between two chunks is
// caught by the one that completes it.  A connection per chunk gave each its
// own redactor and left the join scanned by neither.
func TestAStreamIsOneConnectionAndSaysWhereItEnds(t *testing.T) {
	broker := newStubBroker(t)

	input := strings.Repeat("z", 5*chunkBytes) + "\n"
	var out bytes.Buffer
	if err := redactStream(broker.path, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if got := broker.Conns(); got != 1 {
		t.Errorf("the stream took %d connections, want 1: a redactor per connection "+
			"cannot span the break between two chunks", got)
	}
	more := broker.More()
	if len(more) < 2 {
		t.Fatalf("expected several chunks, got %d", len(more))
	}
	for i, flagged := range more[:len(more)-1] {
		if !flagged {
			t.Errorf("chunk %d did not say another follows, so the broker flushed "+
				"the tail it should have carried", i)
		}
	}
	if more[len(more)-1] {
		t.Error("the last chunk says another follows, so the tail is never flushed " +
			"and the end of the stream is lost")
	}
}

// One request is still one request: the ordinary short redact must not become a
// stream, or a caller that sends one thing and reads one answer would hang.
func TestTextShorterThanAChunkIsASingleRequest(t *testing.T) {
	broker := newStubBroker(t)

	var out bytes.Buffer
	if err := redactStream(broker.path, strings.NewReader("one line\n"), &out); err != nil {
		t.Fatal(err)
	}
	if got := broker.Sizes(); len(got) != 1 {
		t.Errorf("sent %d requests for one short input, want 1", len(got))
	}
	if more := broker.More(); len(more) != 1 || more[0] {
		t.Errorf("a lone chunk said another follows: %v", more)
	}
	if out.String() != "one line\n" {
		t.Errorf("output = %q", out.String())
	}
}

// Empty input costs no connection: dialing would write an audit record for a
// command that printed nothing.
func TestEmptyInputSendsNothing(t *testing.T) {
	broker := newStubBroker(t)

	var out bytes.Buffer
	if err := redactStream(broker.path, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if got := broker.Conns(); got != 0 {
		t.Errorf("empty input opened %d connection(s), want 0", got)
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing", out.String())
	}
}

// A broker it cannot reach must not hand the text over: text that reached no
// redactor is text nobody checked.
func TestABrokerThatIsNotThereWithholdsTheText(t *testing.T) {
	var out bytes.Buffer
	err := redactStream(filepath.Join(t.TempDir(), "absent.sock"),
		strings.NewReader("keep me\n"), &out)
	if err == nil {
		t.Fatal("an unreachable broker was reported as a successful redaction")
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing written", out.String())
	}
}

// A stream that fails part way keeps what was already redacted and stops.
//
// Those chunks went through the redactor and came back covered, so withholding
// them protects nothing; buffering the whole stream to be able to withhold them
// would cost an unbounded buffer and every byte of incremental output. What
// must not appear is the chunk that failed, or anything after it.
//
// The broker goes away by dropping the connection, which is what a restart
// looks like from here.  Unlinking the socket would not do it: a stream holds
// one connection, and an established one outlives the name it was dialed by.
func TestAFailurePartWayThroughKeepsWhatWasRedactedAndStops(t *testing.T) {
	broker := newStubBroker(t)
	broker.dieAfter = 2

	first := strings.Repeat("a", chunkBytes) + "\n"
	rest := strings.Repeat("SENSITIVE\n", 100)

	var out bytes.Buffer
	err := redactStream(broker.path, strings.NewReader(first+rest), &out)
	if err == nil {
		t.Fatal("a broker that went away mid-stream was reported as a success")
	}
	if strings.Contains(out.String(), "SENSITIVE") {
		t.Error("text the broker never saw was written")
	}
	if out.Len() == 0 {
		t.Error("chunks that were redacted successfully were withheld too")
	}
}
