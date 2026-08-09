package guard

import (
	"strings"
	"testing"
)

// The rewrite is exercised directly rather than through the hook's JSON, so
// that a failure names the command that broke rather than a payload.
func bashInput() *payload { return &payload{ToolName: "Bash"} }

// Each of these covers a way the rewrite silently loses a command's output,
// which is worse than refusing it: the agent sees an empty result and reads it
// as success.

// A backgrounded job outlives the brace group, so the wrapper reads and deletes
// the file before the job has written anything.  Go's $ is end of text rather
// than end of line, so the trailing newline a multi-line Bash tool call carries
// has to be treated as trailing space.
func TestABackgroundedCommandIsNotWrappedHoweverItEnds(t *testing.T) {
	for _, command := range []string{
		"npm run dev &",
		"npm run dev &\n",
		"npm run dev & ",
		"cd /srv\nnpm run dev &\n",
		"npm run dev &\n\n",
	} {
		if _, rewritten := wrap(hosts["claude"], command, bashInput()); rewritten {
			t.Errorf("wrapped a backgrounded command: %q", command)
		}
	}
	// "&&" is not backgrounding, and a command ending in one is incomplete
	// rather than backgrounded, so neither should be mistaken for the other.
	if _, rewritten := wrap(hosts["claude"], "make build && make test", bashInput()); !rewritten {
		t.Error("refused to wrap a command containing &&")
	}
}

// Sourced twice in one shell, the inner copy reuses and then clears the outer's
// state: the outer then neither redacts nor removes its temporary file, and the
// agent gets nothing at all.  The emitted form names the wrap script and never
// names the redactor, so matching only "faramir redact" misses it.
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

// Naming the wrapper is not using it.  The script's path appears in this
// project's own documentation and in the wrapper itself, and a command that
// merely mentions it prints whatever else it printed: read as already wrapped,
// that output reaches the transcript unredacted.  Only the form the rewrite
// emits is left alone.
func TestOnlySourcingTheScriptCountsAsWrapped(t *testing.T) {
	for command, wantRewritten := range map[string]bool{
		"cat " + wrapScript():                      true,
		"echo " + wrapScript() + "; ./leak.sh":     true,
		"cd /tmp && source " + wrapScript() + " x": true,
		"source " + wrapScript() + " 'ls -la'":     false,
		". " + wrapScript() + " 'ls -la'":          false,
	} {
		if _, rewritten := wrap(hosts["claude"], command, bashInput()); rewritten != wantRewritten {
			t.Errorf("wrap(%q) rewritten = %v, want %v", command, rewritten, wantRewritten)
		}
	}
}
