package guard

import (
	"strings"
	"testing"
)

// Exercised directly rather than through the hook's JSON, so a failure names
// the command that broke.
func bashInput() *payload { return &payload{ToolName: "Bash"} }

// Each of these covers a way the rewrite silently loses a command's output,
// which the agent reads as success.

// A backgrounded job outlives the brace group, so the wrapper reads and deletes
// the file before it writes. Go's $ is end of text, so a trailing newline
// counts as trailing space.
func TestABackgroundedCommandIsWrappedToStreamHoweverItEnds(t *testing.T) {
	// A backgrounded command's output is redacted as it arrives rather than
	// captured, and the "&" moves outside the wrapper so the whole pipeline is
	// what backgrounds. Capturing it would buffer a command that never exits.
	for _, command := range []string{
		"npm run dev &",
		"npm run dev &\n",
		"npm run dev & ",
		"cd /srv\nnpm run dev &\n",
		"npm run dev &\n\n",
	} {
		got, rewritten := wrap(hosts["claude"], command, bashInput())
		if !rewritten {
			t.Errorf("did not wrap a backgrounded command: %q", command)
			continue
		}
		if !strings.Contains(got, "--stream ") {
			t.Errorf("backgrounded command not streamed: %q -> %q", command, got)
		}
		if !strings.HasSuffix(got, " &") {
			t.Errorf("streamed command lost its backgrounding: %q -> %q", command, got)
		}
	}
	// "&&" is an incomplete command, not backgrounding, so it takes the ordinary
	// capture path. The trailing form is the one that tells the two apart: a
	// command with "&&" in the middle ends in a word either way.
	for _, command := range []string{"make build && make test", "make build &&", "make build && "} {
		got, rewritten := wrap(hosts["claude"], command, bashInput())
		if !rewritten {
			t.Fatalf("refused to wrap a command containing &&: %q", command)
		}
		if strings.Contains(got, "--stream ") {
			t.Errorf("&& was read as backgrounding: %q -> %q", command, got)
		}
	}
}

// Only the last "&" moves out to background the wrapper. An inner one is the
// caller's own, and stripping it too would run in the foreground what they
// asked to background.
func TestOnlyTheTrailingAmpersandIsMovedOut(t *testing.T) {
	got, rewritten := wrap(hosts["claude"], "a & b &", bashInput())
	if !rewritten {
		t.Fatal("refused to wrap a backgrounded command")
	}
	if !strings.Contains(got, "'a & b'") {
		t.Errorf("command = %q, want the inner \"&\" kept inside the quoted word", got)
	}
	if !strings.HasSuffix(got, " &") {
		t.Errorf("command = %q, want it backgrounded", got)
	}
}

// Nothing to wrap is nothing to run: a wrapper sourced with an empty word
// reports the redactor's own exit status for a command that never ran.
func TestACommandThatIsOnlyWhitespaceIsNotWrapped(t *testing.T) {
	for _, command := range []string{"", " ", "\t\n "} {
		if got, rewritten := wrap(hosts["claude"], command, bashInput()); rewritten {
			t.Errorf("wrapped %q -> %q", command, got)
		}
	}
}

// Sourced twice in one shell, the inner copy clears the outer's state and the
// agent gets nothing. The emitted form names the wrap script, never the
// redactor, so matching only "faramir redact" misses it.
func TestARewrittenCommandIsNotRewrittenAgain(t *testing.T) {
	once, rewritten := wrap(hosts["claude"], "echo hello", bashInput())
	if !rewritten {
		t.Fatal("refused to wrap an ordinary command")
	}
	twice, rewritten := wrap(hosts["claude"], once, bashInput())
	if rewritten {
		t.Errorf("wrapped an already-wrapped command:\n  in:  %q\n  out: %q", once, twice)
	}
	if strings.Count(once, wrapScript()) != 1 {
		t.Errorf("the wrapped form names the wrap script %d times, want 1: %q",
			strings.Count(once, wrapScript()), once)
	}
}
