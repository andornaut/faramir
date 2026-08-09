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

// stubBroker answers the redact op by echoing the text back, and records the
// size of every request it was sent.
func stubBroker(t *testing.T) (socketPath string, sizes func() []int) {
	t.Helper()
	socketPath = filepath.Join(t.TempDir(), "b.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); os.Remove(socketPath) })

	var mu sync.Mutex
	var seen []int
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := sockutil.ReadLine(conn, 1<<26)
				if err != nil || len(line) == 0 {
					return
				}
				var request struct {
					Text string `json:"text"`
				}
				if err := json.Unmarshal(line, &request); err != nil {
					return
				}
				mu.Lock()
				seen = append(seen, len(request.Text))
				mu.Unlock()
				_ = sockutil.Send(conn, map[string]any{"output": request.Text})
			}()
		}
	}()
	return socketPath, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), seen...)
	}
}

// The broker's limit is on the encoded line, and chunkBytes is chosen so a
// chunk cannot exceed it however badly it encodes.  A partial buffer plus a
// full ReadSlice would put nearly twice that on the wire, and an oversized
// request comes back as too_large, which passes the text through unredacted.
func TestNoChunkExceedsTheChunkSize(t *testing.T) {
	socketPath, sizes := stubBroker(t)

	// Short lines, so the buffer is nearly always partial when the next
	// ReadSlice lands.
	input := strings.Repeat(strings.Repeat("x", 60)+"\n", 4000)

	var out bytes.Buffer
	if err := redactStream(socketPath, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != input {
		t.Fatalf("output differs from input: %d bytes in, %d out", len(input), out.Len())
	}
	requests := sizes()
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
	socketPath, sizes := stubBroker(t)

	input := strings.Repeat("y", 5*chunkBytes) + "\n"
	var out bytes.Buffer
	if err := redactStream(socketPath, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != input {
		t.Fatalf("output differs: %d bytes in, %d out", len(input), out.Len())
	}
	for i, size := range sizes() {
		if size > chunkBytes {
			t.Errorf("chunk %d carried %d bytes of text, over the %d-byte budget",
				i, size, chunkBytes)
		}
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
func TestAFailurePartWayThroughKeepsWhatWasRedactedAndStops(t *testing.T) {
	socketPath, _ := stubBroker(t)

	// Two chunks' worth, with the broker taken away after the first: long lines
	// so the first chunk flushes before the reader reaches the end.
	first := strings.Repeat("a", chunkBytes) + "\n"
	rest := strings.Repeat("SENSITIVE\n", 100)

	var out bytes.Buffer
	err := redactStream(socketPath, &breakAfter{
		reader: strings.NewReader(first + rest),
		at:     len(first),
		onHalf: func() { os.Remove(socketPath) },
	}, &out)
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

// breakAfter runs onHalf once, as soon as at bytes have been read, so the
// broker can be removed between one chunk and the next.
type breakAfter struct {
	reader *strings.Reader
	at     int
	read   int
	onHalf func()
	fired  bool
}

func (b *breakAfter) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	if !b.fired && b.read >= b.at {
		b.fired = true
		b.onHalf()
	}
	return n, err
}
