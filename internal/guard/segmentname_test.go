package guard

import (
	"strings"
	"testing"
)

// A compound line refused for one of its commands has to say which one. A hook
// answers for the whole tool call, so one refused segment refuses the batch, and
// an agent told only the pattern rewrites whichever part it guesses. The guess
// goes to the wrong half often enough that the rule gets reported as a false
// positive against a command it never matched.
func TestARefusalNamesTheCommandThatMatched(t *testing.T) {
	const command = `grep -ril password roles/ | head -10; echo mid; cat /etc/faramir/age.key`
	pattern, denied := decide(command)
	if !denied {
		t.Fatal("the line should be refused for its last command")
	}
	got := matchingSegment(command, pattern)
	if !strings.Contains(got, "age.key") {
		t.Errorf("the refusal should name the command reading the key, got %q", got)
	}
	for _, innocent := range []string{"head", "echo mid", "grep"} {
		if strings.Contains(got, innocent) {
			t.Errorf("the refusal named %q, which matched nothing: %q", innocent, got)
		}
	}
}

// One command in the line: the pattern is the whole answer already, and quoting
// the line back at the agent adds nothing it does not have.
func TestASingleCommandRefusalNamesNoSegment(t *testing.T) {
	const command = "cat /etc/faramir/config.toml"
	pattern, denied := decide(command)
	if !denied {
		t.Fatal("reading the config directory should be refused")
	}
	if got := matchingSegment(command, pattern); got != "" {
		t.Errorf("a one-command line needs no segment named, got %q", got)
	}
}

// A line that is refused but whose segments each match nothing on their own.
// Segments are matched in a normalised spelling as well as the written one, so a
// pattern can answer for a spelling nobody typed. Quoting a command back that
// the agent did not write is worse than quoting none.
func TestNoSegmentIsNamedWhenNoneMatchesAlone(t *testing.T) {
	// Not refused at all, which is the same path through matchingSegment: no
	// pattern in the file has this source, so the loop finds nothing to report.
	if got := matchingSegment("echo one; echo two", "a pattern no file carries"); got != "" {
		t.Errorf("an unknown pattern should name no segment, got %q", got)
	}
}

// The program a segment runs, which decides whether a patch envelope is examined
// at all. A shell needs no separator before a redirection, so cutting the first
// word on a space alone left `apply_patch<<'EOF'` reading as a program of that
// name and its envelope unread.
func TestFirstWordEndsAtMoreThanASpace(t *testing.T) {
	for _, tc := range []struct{ segment, want string }{
		{"apply_patch", "apply_patch"},
		{"apply_patch 'x'", "apply_patch"},
		{"apply_patch\t'x'", "apply_patch"},
		{"apply_patch<<'EOF'", "apply_patch"},
		{"apply_patch>out", "apply_patch"},
		{"apply_patch<in", "apply_patch"},
		{"  apply_patch  ", "apply_patch"},
		{"/usr/bin/apply_patch<<'EOF'", "/usr/bin/apply_patch"},
	} {
		if got := firstWord(tc.segment); got != tc.want {
			t.Errorf("firstWord(%q) = %q, want %q", tc.segment, got, tc.want)
		}
	}
}
