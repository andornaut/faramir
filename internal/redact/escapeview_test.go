package redact

import (
	"fmt"
	"strings"
	"testing"
)

// A CSI whose final byte the value supplied: the strip is right and the value
// has to come back covered anyway.
func TestADanglingCSIBeforeAValueDoesNotLeakIt(t *testing.T) {
	const value = "hunter2-correct-horse-battery"
	policy := EligibilityPolicy{MinLength: 8}
	for _, tc := range []struct{ name, before string }{
		{"bare introducer", "\x1b["},
		{"introducer and parameters", "\x1b[01;32"},
		{"introducer, parameters and intermediates", "\x1b[01;32 !"},
		{"two introducers", "\x1b[\x1b["},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "db/password", Value: value}}, policy)
			got := r.RedactText(tc.before + value + "\n")
			if strings.Contains(got, value[1:]) {
				t.Fatalf("the value leaked: %q", got)
			}
			if !strings.Contains(got, TokenFor("db/password")) {
				t.Fatalf("no token, so the check had no subject: %q", got)
			}
		})
	}
}

// The same shape arriving in pieces, the sequence in one chunk and the value in
// the next.
func TestADanglingCSIAcrossAChunkBoundaryDoesNotLeak(t *testing.T) {
	const value = "hunter2-correct-horse-battery"
	r := New([]Secret{{Ref: "db/password", Value: value}}, EligibilityPolicy{MinLength: 8})
	out := r.Feed("\x1b[") + r.Feed(value) + r.Flush()
	if strings.Contains(out, value[1:]) {
		t.Fatalf("the value leaked across the join: %q", out)
	}
	if !strings.Contains(out, TokenFor("db/password")) {
		t.Fatalf("no token: %q", out)
	}
}

// A well-formed sequence must still be removed, and must not be counted as a
// redaction or leave the letter it ends on behind.
func TestAWellFormedSequenceIsStillStripped(t *testing.T) {
	const value = "hunter2-correct-horse-battery"
	r := New([]Secret{{Ref: "db/password", Value: value}}, EligibilityPolicy{MinLength: 8})
	got := r.RedactText("\x1b[32m" + value + "\x1b[0m\n")
	if want := TokenFor("db/password") + "\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if n := len(r.Summary()); n != 1 {
		t.Fatalf("counted %d value(s), want 1", n)
	}
	if r.Summary()[0].Count != 1 {
		t.Fatalf("counted the value %d times, want once", r.Summary()[0].Count)
	}
}

// The view is built in the same walk that strips, so the stripped half has to
// stay exactly what stripping alone produced: the output every other test in
// this package is written against.
func TestTheStrippedHalfIsUnchanged(t *testing.T) {
	want := func(text string) string {
		return strings.ReplaceAll(ansiRE.ReplaceAllString(text, ""), "\r\n", "\n")
	}
	corpus := []string{
		"", "plain text", "a\r\nb", "a\rb", "a\r\r\nb", "trailing\r",
		"\x1b[32mgreen\x1b[0m", "\x1b[", "\x1b[01;32", "\x1b]0;title\x07",
		"\x1b]0;unterminated", "\x1bP dcs \x1b\\", "\x1b(B", "\x1bA",
		"a\x00b\x7fc", "\r\x1b[32m\n", "\x1b[32m\r\n", "mixed \x1b[1m\r\n tail\r",
		"\x1b[\x1b[\x1b[", "é\x1b[32mé", "\x1b[999999999m",
	}
	for _, text := range corpus {
		if got, _ := stripANSIView(text); got != want(text) {
			t.Errorf("stripANSIView(%q) = %q, want %q", text, got, want(text))
		}
	}
	// And on bytes nobody chose, where a sequence lands where it likes.
	alphabet := []byte("ab\r\n\x1b[;m0 !\x00\x07\\")
	seed := uint32(2463534242)
	next := func() byte {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		return alphabet[int(seed)%len(alphabet)]
	}
	for range 2000 {
		b := make([]byte, 1+int(next())%40)
		for i := range b {
			b[i] = next()
		}
		text := string(b)
		if got, _ := stripANSIView(text); got != want(text) {
			t.Fatalf("stripANSIView(%q) = %q, want %q", text, got, want(text))
		}
	}
}

// Every byte of the view has to name a place in the stripped text, or a match
// maps onto the wrong span.
func TestTheViewIndexCoversEveryByteAndTheEnd(t *testing.T) {
	for _, text := range []string{
		"\x1b[32mgreen\x1b[0m", "\x1b[value", "a\r\n\x1b[b", "", "\x1b[\x1b[x",
	} {
		clean, v := stripANSIView(text)
		if v == nil {
			continue // nothing to strip, so there is no view and no map
		}
		if len(v.clean) != len(v.view)+1 {
			t.Fatalf("%q: %d index entries for %d view bytes", text, len(v.clean), len(v.view))
		}
		for i, at := range v.clean {
			if at < 0 || at > len(clean) {
				t.Fatalf("%q: index[%d] = %d, outside a %d-byte text", text, i, at, len(clean))
			}
			if i > 0 && at < v.clean[i-1] {
				t.Fatalf("%q: index[%d] = %d goes backwards from %d", text, i, at, v.clean[i-1])
			}
		}
	}
}

// The other half of the hot path: output that carries colour, where the view
// above is built and scanned rather than skipped. BenchmarkRedactorFeed is the
// same work over text with no escapes in it.
func BenchmarkRedactorFeedColoured(b *testing.B) {
	for _, n := range []int{10, 50, 200} {
		b.Run(fmt.Sprintf("secrets=%d", n), func(b *testing.B) {
			secrets := manySecrets(n)
			chunk := strings.Repeat("\x1b[32mordinary\x1b[0m build output line\n", 2400) +
				secrets[n/2].Value + "\n"
			b.SetBytes(int64(len(chunk)))
			b.ReportAllocs()
			for b.Loop() {
				r := New(secrets, DefaultPolicy())
				r.Feed(chunk)
				r.Flush()
			}
		})
	}
}
