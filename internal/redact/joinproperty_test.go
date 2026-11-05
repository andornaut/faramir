package redact

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// Property tests over the stream: random input around one value, fed in the
// pieces a real caller would send, and the value has to come back as its
// token every time. A failure prints the seed and the iteration, which rebuild
// the input exactly:
//
//	go test ./internal/redact -run <Test> -args -redact.seed=<seed> -redact.iterations=<n>
var (
	propertySeed       = flag.Uint64("redact.seed", 0, "seed for the redact property tests; 0 picks one from the clock")
	propertyIterations = flag.Int("redact.iterations", 0, "iterations for the redact property tests; 0 keeps each test's default")
)

const joinValue = "hunter2-correct-horse-battery"

func propertyRun(t *testing.T, defaultIterations int) (seed uint64, iterations int) {
	t.Helper()
	seed, iterations = *propertySeed, defaultIterations
	if seed == 0 {
		seed = uint64(time.Now().UnixNano())
	}
	if *propertyIterations > 0 {
		iterations = *propertyIterations
	}
	t.Logf("seed %d, %d iterations", seed, iterations)
	return seed, iterations
}

// propertyRand is iteration i's generator.
func propertyRand(seed uint64, i int) *rand.Rand {
	return rand.New(rand.NewPCG(seed, uint64(i))) //nolint:gosec // G404: seeded on purpose, so a failing input can be rebuilt
}

// clientChunkBytes and the chunking below are what `faramir redact` does in
// brokerclient.RedactStream: lines gathered into requests of at most 32 KiB, a
// line longer than the read buffer sent in pieces, an incomplete UTF-8 tail
// held for the next request, and every request's text coerced to valid UTF-8
// by the JSON encoding it travels in.
const clientChunkBytes = 32 << 10

func clientChunks(input []byte) []string {
	reader := bufio.NewReaderSize(bytes.NewReader(input), clientChunkBytes-4)
	var out, buf []byte
	var chunks []string
	send := func(more bool) {
		out, buf = buf, nil
		if more {
			out, buf = SplitIncompleteTail(out)
			if len(out) == 0 {
				return
			}
			buf = append([]byte(nil), buf...)
		}
		chunks = append(chunks, string([]rune(string(out))))
	}
	for {
		line, err := reader.ReadSlice('\n')
		if len(buf) > 0 && len(buf)+len(line) > clientChunkBytes {
			send(true)
		}
		buf = append(buf, line...)
		if errors.Is(err, bufio.ErrBufferFull) {
			send(true)
			continue
		}
		if len(buf) >= clientChunkBytes {
			send(true)
		}
		if err != nil {
			send(false)
			return chunks
		}
	}
}

func feedAll(r *Redactor, chunks []string) string {
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString(r.Feed(c))
	}
	b.WriteString(r.Flush())
	return b.String()
}

// leakedPiece is the first 8-byte piece of value present in out, or "".
func leakedPiece(out, value string) string {
	for i := 0; i+8 <= len(value); i++ {
		if strings.Contains(out, value[i:i+8]) {
			return value[i : i+8]
		}
	}
	return ""
}

func checkJoinOutput(t *testing.T, label string, input []byte, out string) {
	t.Helper()
	at := bytes.Index(input, []byte(joinValue))
	around := hex.EncodeToString(input[max(at-64, 0):min(at+len(joinValue)+64, len(input))])
	if piece := leakedPiece(out, joinValue); piece != "" {
		t.Fatalf("%s: %q of the value is in the output; input around it: %s", label, piece, around)
	}
	if !strings.Contains(out, TokenFor("db/password")) {
		t.Fatalf("%s: no token, so the value was dropped unmatched; input around it: %s", label, around)
	}
}

// Random binary, the value 12 bytes short of the first request boundary, and
// 2000 more random bytes: tests/e2e/check-stream.sh's case, chunked the way the
// client chunks it. Random binary holds escape introducers and terminators at
// random, so this crosses every arrangement of a sequence around the value
// that the e2e run can, at its rate. Half the inputs carry no newline before
// the value, which puts the request boundary inside it.
func TestAValueInRandomBinaryOnAJoinIsTokenized(t *testing.T) {
	seed, iterations := propertyRun(t, 300)
	for i := range iterations {
		rng := propertyRand(seed, i)
		input := make([]byte, 0, clientChunkBytes+len(joinValue)+2000)
		for range clientChunkBytes - 12 {
			b := byte(rng.UintN(256))
			if i%2 == 1 && b == '\n' {
				b = ' '
			}
			input = append(input, b)
		}
		input = append(input, joinValue...)
		for range 2000 {
			input = append(input, byte(rng.UintN(256)))
		}
		r := New([]Secret{{Ref: "db/password", Value: joinValue}}, EligibilityPolicy{MinLength: 8})
		checkJoinOutput(t, fmt.Sprintf("iteration %d", i), input, feedAll(r, clientChunks(input)))
	}
}

// The same property where it is dense: short input drawn mostly from the bytes
// stage 1 acts on, the value somewhere in it, and the stream cut into random
// pieces with one cut near the value. Random binary meets an OSC around the
// value about once in a thousand inputs; this meets one in most.
func TestAValueAmongEscapeBytesIsTokenizedHoweverTheStreamIsCut(t *testing.T) {
	seed, iterations := propertyRun(t, 20000)
	alphabet := []byte("\x1b\x1b\x1b\x1b[[]]]PX^_()B0\\\\\x07\x07\r\r\n\n\x00\x01\x7f;;0123 !-mhHaz\xc3\xa9")
	for i := range iterations {
		rng := propertyRand(seed, i)
		pad := func(n int) []byte {
			out := make([]byte, n)
			for k := range out {
				if rng.UintN(8) == 0 {
					out[k] = byte(rng.UintN(256))
				} else {
					out[k] = alphabet[rng.UintN(uint(len(alphabet)))]
				}
			}
			return out
		}
		input := append(pad(int(rng.UintN(300))), joinValue...)
		at := len(input) - len(joinValue)
		input = append(input, pad(int(rng.UintN(300)))...)
		// One cut within 40 bytes of the value's first byte, inside it included,
		// and up to four more anywhere.
		cuts := []int{min(max(at+int(rng.UintN(80))-40, 0), len(input))}
		for range rng.UintN(5) {
			cuts = append(cuts, int(rng.UintN(uint(len(input)))))
		}
		r := New([]Secret{{Ref: "db/password", Value: joinValue}}, EligibilityPolicy{MinLength: 8})
		out := feedAll(r, cutAt(input, cuts))
		checkJoinOutput(t, fmt.Sprintf("iteration %d, cuts %v", i, cuts), input, out)
		// And the one-shot answer, which has no join to blame.
		checkJoinOutput(t, fmt.Sprintf("iteration %d, one shot", i), input,
			New([]Secret{{Ref: "db/password", Value: joinValue}}, EligibilityPolicy{MinLength: 8}).RedactText(string(input)))
	}
}

// cutAt splits input at the given offsets, in any order, dropping empty pieces.
func cutAt(input []byte, cuts []int) []string {
	sorted := slices.Sorted(slices.Values(cuts))
	var out []string
	prev := 0
	for _, c := range append(sorted, len(input)) {
		if c > prev {
			out = append(out, string(input[prev:c]))
			prev = c
		}
	}
	return out
}
