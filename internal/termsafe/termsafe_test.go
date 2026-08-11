package termsafe

import (
	"strings"
	"testing"
)

// What redact.Feed leaves behind is what this has to catch.  The pairs below
// were measured against it rather than assumed: CSI, OSC and the C0 controls are
// stripped before anything reaches a prompt or the audit log, and these two are
// not.
func TestWhatSurvivesRedactionIsRendered(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		// Only CRLF is normalised, so a lone CR passes through.  It returns the
		// cursor, and the rest of the line overwrites what came before it.
		{"carriage return", "site.yml\rls -la"},
		// ESC c is a full terminal reset, which on many emulators takes the
		// scrollback with it.  No pattern in the strip set matches ESC followed by
		// a byte outside @-Z and \\-_.
		{"terminal reset", "site.yml\x1bc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for what, got := range map[string]string{
				"Arg":  Arg(tc.in),
				"Line": Line(tc.in),
			} {
				if strings.ContainsAny(got, "\r\x1b") {
					t.Errorf("%s(%q) = %q, want no byte a terminal acts on", what, tc.in, got)
				}
			}
		})
	}
}

// Ordinary text is returned as it was written.  A line full of quotation marks
// or escapes is one that is read less carefully, which is the thing this exists
// to protect.
func TestOrdinaryTextIsLeftAlone(t *testing.T) {
	for _, in := range []string{
		"ansible-playbook",
		"/srv/ansible-ctrl",
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

// Bound says that it truncated.  Silent truncation would let a long value end
// the displayed text wherever it liked.
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
