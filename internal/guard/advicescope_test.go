package guard

import (
	"strings"
	"testing"
)

// The segment the refusal quotes must be the one that was refused, not one the
// decision deliberately let through. A line that opens with the wrapper and
// chains a read is denied for the read, so that is the command to change.
func TestTheQuotedSegmentIsNotTheExemptedWrapper(t *testing.T) {
	command := "source " + wrapScript() + " 'ls' && head -1 /etc/faramir/age.key"
	pattern, denied := decide(command)
	if !denied {
		t.Fatal("a line reaching the age key is allowed")
	}
	got := matchingSegment(command, pattern)
	if strings.Contains(got, wrapScript()) {
		t.Errorf("the refusal quotes the wrapper invocation, which it allowed: %q", got)
	}
	if !strings.Contains(got, "head") {
		t.Errorf("the refusal quotes %q, which is not the command that was refused", got)
	}
}

// A name formed by appending to the wrapper's own is a different file, and one
// inside a declared directory. The exemption is for the wrapper, not for
// anything whose path starts the same way.
func TestASiblingOfTheWrapperIsNotExempt(t *testing.T) {
	for _, command := range []string{
		"source " + wrapScript() + ".orig 'ls'",
		". " + wrapScript() + ".bak 'ls'",
	} {
		if _, denied := decide(command); !denied {
			t.Errorf("%q is allowed, and it names a file the wrapper only prefixes", command)
		}
	}
}
