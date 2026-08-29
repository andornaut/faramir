package redact

import (
	"fmt"
	"strings"
	"testing"
)

// A value spanning lines, and the shapes ordinary tools leave it in. Matching
// the stored spelling alone catches only the first of these: everything else
// either puts characters between the lines or emits one line without the other,
// and against a single literal needle every one of them goes out in the clear
// with nothing counted as redacted.
//
// The routes are not adversarial and that is the point of the test. Numbering a
// file, indenting it, searching it and expanding a variable unquoted are what an
// agent does while working, not what it does to defeat a redactor.
func TestAValueSpanningLinesIsRedactedHoweverItsLinesAreSeparated(t *testing.T) {
	const (
		first  = "CANARY-multiline-first-0123456789abcdef"
		second = "CANARY-multiline-second-fedcba9876543210"
		ref    = "agenttest/multiline"
	)
	value := first + "\n" + second

	for _, tc := range []struct {
		name string
		text string
	}{
		{"as stored", value},
		{"cat -n", "     1\t" + first + "\n     2\t" + second},
		{"nl", "     1  " + first + "\n     2  " + second},
		{"grep -n", "1:" + first + "\n2:" + second},
		{"sed indent", "    " + first + "\n    " + second},
		{"unquoted expansion word-splits to one space", first + " " + second},
		{"only the second line, as sed -n 2p prints it", second},
		{"only the first line", first},
		{"CRLF rewrap", first + "\r\n" + second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := New([]Secret{{Ref: ref, Value: value}}, EligibilityPolicy{MinLength: 8}).
				RedactText(tc.text)
			for _, leak := range []string{first, second} {
				if strings.Contains(out, leak) {
					t.Errorf("a line of the value survived: %q", out)
				}
			}
			if !strings.Contains(out, TokenFor(ref)) {
				t.Errorf("no token, so nothing was matched and nothing would be counted: %q", out)
			}
		})
	}
}

// The stream path, one line per Feed, which is how a slow command arrives. The
// second line must be redacted on its own rather than held for a first line that
// has already gone out.
func TestASecondLineArrivingAloneIsStillRedacted(t *testing.T) {
	const (
		first  = "CANARY-stream-first-0123456789abcdef"
		second = "CANARY-stream-second-fedcba9876543210"
		ref    = "agenttest/stream"
	)
	r := New([]Secret{{Ref: ref, Value: first + "\n" + second}}, EligibilityPolicy{MinLength: 8})
	var out strings.Builder
	out.WriteString(r.Feed("1:" + first + "\n"))
	out.WriteString(r.Feed("2:" + second + "\n"))
	out.WriteString(r.Flush())
	got := out.String()
	for _, leak := range []string{first, second} {
		if strings.Contains(got, leak) {
			t.Fatalf("a line survived the stream: %q", got)
		}
	}
}

// A line under MinLength is not registered, so a value can be partly covered.
// That is the same rule a short single-line value already meets, and the test
// exists so the gap is a decision on the record rather than a surprise: the long
// line is redacted and the short one is not.
func TestALineUnderMinLengthIsNotRedactedOnItsOwn(t *testing.T) {
	const (
		long  = "CANARY-long-line-0123456789abcdef"
		short = "abc"
		ref   = "agenttest/short"
	)
	r := New([]Secret{{Ref: ref, Value: long + "\n" + short}}, EligibilityPolicy{MinLength: 8})
	out := r.RedactText(fmt.Sprintf("1:%s\n2:%s", long, short))
	if strings.Contains(out, long) {
		t.Errorf("the long line should be redacted on its own: %q", out)
	}
	if !strings.Contains(out, short) {
		t.Errorf("a line under MinLength is expected to survive; if this now fails, "+
			"the policy changed and the docs saying so need to change with it: %q", out)
	}
}
