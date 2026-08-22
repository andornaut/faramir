package termsafe

import (
	"strings"
	"testing"
)

// What redact.Feed leaves behind is what this has to catch. The pairs below
// were measured against it rather than assumed: CSI, OSC and the C0 controls are
// stripped before anything reaches a prompt or the audit log, and these two are
// not.
func TestWhatSurvivesRedactionIsRendered(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		// Only CRLF is normalised, so a lone CR passes through. It returns the
		// cursor, and the rest of the line overwrites what came before it.
		{"carriage return", "site.yml\rls -la"},
		// ESC c is a full terminal reset, which on many emulators takes the
		// scrollback with it. No pattern in the strip set matches ESC followed by
		// a byte outside @-Z and \\-_.
		{"terminal reset", "site.yml\x1bc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, r := range []struct {
				what string
				got  string
			}{
				{"Arg", Arg(tc.in)},
				{"Line", Line(tc.in)},
			} {
				if strings.ContainsAny(r.got, "\r\x1b") {
					t.Errorf("%s(%q) = %q, want no byte a terminal acts on", r.what, tc.in, r.got)
				}
			}
		})
	}
}

// Ordinary text is returned as it was written. A line full of quotation marks
// or escapes is one that is read less carefully, which is the thing this exists
// to protect.
func TestOrdinaryTextIsLeftAlone(t *testing.T) {
	for _, in := range []string{
		"ansible-playbook",
		"/srv/ansible",
		"ok: [host.example.com]",
		"héllo wörld",
	} {
		if got := Line(in); got != in {
			t.Errorf("Line(%q) = %q, want it unchanged", in, got)
		}
	}
	if got := Arg("ansible-playbook"); got != "ansible-playbook" {
		t.Errorf("Arg = %q, want it unquoted", got)
	}
}

// Line keeps a tab: it is layout an operator wants, and it cannot move the
// cursor anywhere a reader would not expect.
func TestLineKeepsTabs(t *testing.T) {
	if got := Line("a\tb"); got != "a\tb" {
		t.Errorf("Line = %q, want the tab kept", got)
	}
}

// Line neither quotes nor truncates: it renders the text an operator came to
// read, and wrapping or cutting it would make the log worse at its one job.
func TestLineDoesNotQuoteOrTruncate(t *testing.T) {
	long := strings.Repeat("output ", 500)
	if got := Line(long); got != long {
		t.Errorf("Line truncated or altered a %d-byte line", len(long))
	}
	if got := Line(`say "hi"`); got != `say "hi"` {
		t.Errorf("Line(%q) = %q, want the quotes left as written", `say "hi"`, got)
	}
}

// Arg quotes rather than strips, so an argument that held something is one the
// operator can see held it.
func TestArgQuotesRatherThanStrips(t *testing.T) {
	got := Arg("site.yml\rls -la")
	if !strings.Contains(got, `\r`) {
		t.Errorf("Arg = %q, want the carriage return shown as an escape", got)
	}
}

// Silent truncation would let a long value end the displayed text wherever it
// liked.
func TestBoundSaysItTruncated(t *testing.T) {
	got := Bound(strings.Repeat("a", 1000), 100)
	if len(got) > 200 {
		t.Errorf("Bound returned %d bytes for a limit of 100", len(got))
	}
	if !strings.Contains(got, "more bytes") {
		t.Errorf("Bound = %q, want the truncation said", got)
	}
	// A rune is never cut in half.
	if got := Bound("héllo", 2); strings.HasPrefix(got, "h\xc3") {
		t.Errorf("Bound = %q, want the partial rune dropped", got)
	}
}

// C1 is the other half of what a terminal acts on, and the strip set does not
// reach it: it matches CSI as ESC '[', so U+009B, the single-character form of
// the same introducer, arrives here untouched and a following "2J" clears the
// screen of a terminal that honours 8-bit controls. Arg escapes these already,
// strconv.Quote treating them as non-printable, so this is the two renderers
// agreeing rather than a new rule.
func TestC1ControlsAreEscaped(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"8-bit CSI", "ok: [host]\u009b2J"},
		{"8-bit OSC", "ok: [host]\u009d0;title\u009c"},
		{"delete", "ok: [host]\u007f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Line(tc.in)
			if got == tc.in {
				t.Fatalf("Line left %q unchanged", tc.in)
			}
			for _, r := range got {
				if r >= 0x7f && r <= 0x9f {
					t.Fatalf("Line(%q) = %q, want no rune a terminal acts on", tc.in, got)
				}
			}
		})
	}
}

// A byte that is not valid UTF-8 is not the rune it would have encoded. Ranging
// a string by rune yields U+FFFD for it, which unsafeRune calls safe, so a lone
// 0x9b used to be written straight through: on a terminal honouring 8-bit
// controls that is the CSI introducer, and "\x9b2J" clears the screen. Output
// arrives here through the redactor, which replaces an invalid byte already,
// but a recorded path or a detail string does not.
func TestLineEscapesEveryByteATerminalWouldActOn(t *testing.T) {
	actionable := func(s string) []byte {
		var out []byte
		for i := range len(s) {
			if b := s[i]; (b < 0x20 && b != '\t' && b != '\n') || (b >= 0x7f && b <= 0x9f) {
				out = append(out, b)
			}
		}
		return out
	}
	for b := range 256 {
		got := Line("a" + string([]byte{byte(b)}) + "b")
		if left := actionable(got); len(left) > 0 {
			t.Errorf("byte %#02x survives as % x in %q", b, left, got)
		}
	}
}

// And ordinary text is returned as it was written, tabs and multi-byte runes
// included: this is what an operator came to read.
func TestLineLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{
		"ordinary text", "with\ttabs", "\u65e5\u672c\u8a9e caf\u00e9", "a/b/c.sops.yml", "",
	} {
		if got := Line(s); got != s {
			t.Errorf("Line(%q) = %q, want it unchanged", s, got)
		}
	}
}

// Field is what an escalation prompt shows for one field: the account that
// asked, the working directory, the program a relative argv[0] resolved to.
// Each is somebody else's text, so it is escaped and quoted like an argument,
// and bounded as well, a question that scrolled off the top being one nobody
// read.
func TestFieldEscapesQuotesAndBounds(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Ordinary text is left bare, so a prompt is not full of quotes.
		{"/srv/ansible", "/srv/ansible"},
		{"operator", "operator"},
		// Anything a terminal would act on, or that needs a boundary shown.
		{"/srv/a b", `"/srv/a b"`},
		{"a\rb", `"a\rb"`},
		{"a\x1bcb", `"a\x1bcb"`},
	} {
		if got := Field(tc.in, 200); got != tc.want {
			t.Errorf("Field(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// And bounded: the limit is on the text, and a marker says what was dropped
	// and where the whole of it is, so a truncated field is never read as the
	// whole value.
	long := strings.Repeat("x", 300)
	got := Field(long, 40)
	head, marker, found := strings.Cut(got, "...")
	if !found {
		t.Fatalf("Field(300 bytes, 40) = %q, with no truncation marker", got)
	}
	if len(head) != 40 {
		t.Errorf("kept %d bytes of text, want 40: %q", len(head), head)
	}
	if !strings.Contains(marker, "260 more bytes") {
		t.Errorf("the marker does not say how much was dropped: %q", marker)
	}
}

// Nothing a terminal acts on survives Field either, at any length.
func TestFieldLeavesNothingActionable(t *testing.T) {
	for r := rune(0); r <= 0x9f; r++ {
		if !Actionable(r) {
			continue
		}
		out := Field("a"+string(r)+"b", 200)
		for _, got := range out {
			if Actionable(got) && got != '\t' {
				t.Errorf("Field(%q) leaves %q", r, out)
				break
			}
		}
	}
}
