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

// The limit the broker enforces is on the encoded line, not on the text, and
// chunkBytes is chosen so a chunk cannot exceed it however badly it encodes.
// A partial buffer plus a full ReadSlice would put nearly twice that on the
// wire, and the broker answers an oversized request with too_large, which the
// filter handles by passing the text through UNREDACTED.  So the invariant is
// about the size of the request, not about the output being correct.
func TestNoChunkExceedsTheChunkSize(t *testing.T) {
	socketPath, sizes := stubBroker(t)

	// Short lines, so many of them accumulate into one chunk and the buffer is
	// nearly always partial when the next ReadSlice lands.
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

// A line longer than the reader's buffer arrives in pieces, and each piece is
// its own chunk rather than being grown without bound.
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

// The filter is fail-open by design: a broker it cannot reach must not swallow
// the text it was given.
func TestTextSurvivesABrokerThatIsNotThere(t *testing.T) {
	var out bytes.Buffer
	stderr := os.Stderr
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stderr = devNull
	defer func() { os.Stderr = stderr; devNull.Close() }()

	err := redactStream(filepath.Join(t.TempDir(), "absent.sock"),
		strings.NewReader("keep me\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "keep me\n" {
		t.Errorf("output = %q", out.String())
	}
}
