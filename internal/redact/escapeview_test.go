package redact

import (
	"fmt"
	"strings"
	"testing"
)

// A value written straight after an escape introducer that has no terminator
// of its own, so the sequence takes the value's first byte or all of it. The
// strip is right, and the value has to come back as its token anyway, whole or
// across a stream join.
var escapeTakesValueCases = []struct {
	name, value, before, after string
}{
	{"CSI, bare introducer", "hunter2-correct-horse-battery", "\x1b[", ""},
	{"CSI, parameters", "hunter2-correct-horse-battery", "\x1b[01;32", ""},
	{"CSI, parameters and intermediates", "hunter2-correct-horse-battery", "\x1b[01;32 !", ""},
	{"CSI, two introducers", "hunter2-correct-horse-battery", "\x1b[\x1b[", ""},
	{"CSI after a CR", "hunter2-correct-horse-battery", "\r\x1b[", ""},
	{"OSC ended by BEL", "hunter2-correct-horse-battery", "\x1b]", "\x07"},
	{"OSC ended by BEL further on", "hunter2-correct-horse-battery", "\x1b]0;", " more\x07"},
	{"OSC ended by ST", "hunter2-correct-horse-battery", "\x1b]", "\x1b\\"},
	{"OSC holding a CRLF", "hunter2-correct-horse-battery", "\x1b]0;\r\n", "\r\n\x07"},
	{"DCS", "hunter2-correct-horse-battery", "\x1bP", "\x1b\\"},
	{"SOS", "hunter2-correct-horse-battery", "\x1bX", "\x1b\\"},
	{"PM", "hunter2-correct-horse-battery", "\x1b^", "\x1b\\"},
	{"APC", "hunter2-correct-horse-battery", "\x1b_", "\x1b\\"},
	{"two-character escape", "Hunter2-correct-horse-battery", "\x1b", ""},
	{"charset selection, G0", "Battery-horse-correct-hunter2", "\x1b(", ""},
	{"charset selection, G1", "Battery-horse-correct-hunter2", "\x1b)", ""},
	{"stray control", "hunter2-correct-horse-battery", "\x01", ""},
}

func checkEscapeTakesValue(t *testing.T, got, value string) {
	t.Helper()
	if piece := leakedPiece(got, value); piece != "" {
		t.Fatalf("%q of the value is in the output: %q", piece, got)
	}
	if !strings.Contains(got, TokenFor("db/password")) {
		t.Fatalf("no token, so the value went unmatched: %q", got)
	}
}

func TestAnEscapeThatTakesAValueDoesNotHideIt(t *testing.T) {
	for _, tc := range escapeTakesValueCases {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "db/password", Value: tc.value}}, EligibilityPolicy{MinLength: 8})
			got := r.RedactText("before " + tc.before + tc.value + tc.after + " after\n")
			checkEscapeTakesValue(t, got, tc.value)
			if n := r.Summary()[0].Count; n != 1 {
				t.Errorf("counted %d time(s), want once: %q", n, got)
			}
		})
	}
}

// The same arrangements with the stream cut at every byte from just before
// the introducer to just after the terminator. Each sequence here is shorter
// than maxEscapeLen, so the stream holds it whole and has to give the one-shot
// answer exactly.
func TestAnEscapeThatTakesAValueDoesNotHideItAcrossAJoin(t *testing.T) {
	lead := strings.Repeat("ordinary output\n", 20)
	for _, tc := range escapeTakesValueCases {
		t.Run(tc.name, func(t *testing.T) {
			input := lead + tc.before + tc.value + tc.after + " after\n"
			want := New([]Secret{{Ref: "db/password", Value: tc.value}}, EligibilityPolicy{MinLength: 8}).RedactText(input)
			for cut := len(lead) - 4; cut <= len(input)-len(" after\n")+4; cut++ {
				r := New([]Secret{{Ref: "db/password", Value: tc.value}}, EligibilityPolicy{MinLength: 8})
				got := r.Feed(input[:cut]) + r.Feed(input[cut:]) + r.Flush()
				checkEscapeTakesValue(t, got, tc.value)
				if got != want {
					t.Fatalf("cut at %d: streamed %q, one shot %q", cut, got, want)
				}
			}
		})
	}
}

// A value an OSC took whole has nothing left in the stripped text, so its token
// stands where the sequence stood.
func TestAValueAnOSCTookWholeIsReplacedWhereTheSequenceStood(t *testing.T) {
	const value = "hunter2-correct-horse-battery"
	token := TokenFor("db/password")
	for _, tc := range []struct{ name, in, want string }{
		{"between text", "before \x1b]0;" + value + "\x07 after", "before " + token + " after"},
		{"at the start", "\x1b]0;" + value + "\x07after", token + "after"},
		{"the whole text", "\x1b]0;" + value + "\x07", token},
		{"a title with no value", "a\x1b]0;title\x07b", "ab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "db/password", Value: value}}, EligibilityPolicy{MinLength: 8})
			if got := r.RedactText(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
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
		if got, _, _ := stripANSIViewSrc(text); got != want(text) {
			t.Errorf("stripANSIViewSrc(%q) = %q, want %q", text, got, want(text))
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
		if got, _, _ := stripANSIViewSrc(text); got != want(text) {
			t.Fatalf("stripANSIViewSrc(%q) = %q, want %q", text, got, want(text))
		}
	}
}

// Every byte of the view has to name the input byte it came from, or a match
// maps onto the wrong span.
func TestTheViewIndexCoversEveryByteAndTheEnd(t *testing.T) {
	check := func(text string) {
		t.Helper()
		_, v, _ := stripANSIViewSrc(text)
		if v == nil {
			return // no sequence removed, so there is no view and no map
		}
		if len(v.raw) != len(v.view)+1 || v.raw[len(v.view)] != len(text) {
			t.Fatalf("%q: %d index entries for %d view bytes, ending at %d", text, len(v.raw), len(v.view), v.raw[len(v.raw)-1])
		}
		for i := range len(v.view) {
			if at := v.raw[i]; at < 0 || at >= len(text) || text[at] != v.view[i] {
				t.Fatalf("%q: view byte %d (%q) maps to input offset %d", text, i, v.view[i], at)
			}
			if i > 0 && v.raw[i] <= v.raw[i-1] {
				t.Fatalf("%q: index[%d] = %d does not go forwards from %d", text, i, v.raw[i], v.raw[i-1])
			}
		}
	}
	for _, text := range []string{
		"\x1b[32mgreen\x1b[0m", "\x1b[value", "a\r\n\x1b[b", "", "\x1b[\x1b[x",
		"\x1b]0;title\x07", "\x1b]0;a\r\nb\x1b\\", "\r\x1b[32m\n", "\x1bP\x01x\x1b\\",
	} {
		check(text)
	}
	for _, text := range randomEscapeText(2463534242, 2000) {
		check(text)
	}
}

// randomEscapeText is n short strings over an alphabet dense in what stage 1
// acts on, so a sequence lands where it likes.
func randomEscapeText(seed uint32, n int) []string {
	alphabet := []byte("ab\r\n\x1b[];mP(B0 !\x00\x07\\")
	next := func() byte {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		return alphabet[int(seed)%len(alphabet)]
	}
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 1+int(next())%40)
		for j := range b {
			b[j] = next()
		}
		out[i] = string(b)
	}
	return out
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
				r := New(secrets, defaultPolicy())
				r.Feed(chunk)
				r.Flush()
			}
		})
	}
}

// What a PTY delivers: every line ends in CRLF, so stage 1 runs on all of it,
// but there is no escape sequence and so no second haystack to build.
func BenchmarkRedactorFeedCRLF(b *testing.B) {
	for _, n := range []int{10, 50, 200} {
		b.Run(fmt.Sprintf("secrets=%d", n), func(b *testing.B) {
			secrets := manySecrets(n)
			chunk := strings.Repeat("ordinary build output line\r\n", 2400) +
				secrets[n/2].Value + "\r\n"
			b.SetBytes(int64(len(chunk)))
			b.ReportAllocs()
			for b.Loop() {
				r := New(secrets, defaultPolicy())
				r.Feed(chunk)
				r.Flush()
			}
		})
	}
}
