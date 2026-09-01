package doctor

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// What the registration says about which tools reach the guard. A matcher
// narrower than every tool leaves the file tools to the deny rules beside it,
// and those are applied in some of the agent's permission modes and not others,
// so a read refused on paper is a read nothing refuses.
func TestHookMatchersReadsTheGuardsRegistration(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"every tool", `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[
			{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`, []string{"*"}},
		{"shell only, which is the stale shape", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
			{"type":"command","command":"/usr/local/bin/faramir guard --deny-only"}]}]}}`, []string{"Bash"}},
		// A group with no matcher key at all. Absent is not "*", and reporting it
		// as narrow is the safe way to be wrong: the operator re-runs an enrolment
		// that was going to rewrite the file anyway.
		{"no matcher named", `{"hooks":{"PreToolUse":[{"hooks":[
			{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`, []string{""}},
		// Somebody else's hook, which says nothing about faramir's reach.
		{"another tool's hook", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
			{"type":"command","command":"/usr/bin/some-linter"}]}]}}`, nil},
		{"two groups, one of them faramir's", `{"hooks":{"PreToolUse":[
			{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/bin/some-linter"}]},
			{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`,
			[]string{"*"}},
		{"no hooks at all", `{"permissions":{"deny":[]}}`, nil},
		// Neither of these is this check's question: what a file says when it is
		// missing or unreadable is diagnoseAgentRules', and two checks reporting
		// one missing file is one report too many.
		{"not json", `{`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _ := hookMatchers(path); !slices.Equal(got, tc.want) {
				t.Errorf("hookMatchers = %q, want %q", got, tc.want)
			}
		})
	}
}

// Absent and unreadable are different answers, and the check reports them
// differently: a missing file is diagnoseAgentRules' question, while a file that
// is there and cannot be opened is this check's own case seen from the outside,
// where a stale registration and an unreadable one look identical.
func TestHookMatchersTellsAbsentFromUnreadable(t *testing.T) {
	dir := t.TempDir()

	got, read := hookMatchers(filepath.Join(dir, "absent.json"))
	if got != nil {
		t.Errorf("a file that is not there should report nothing, got %q", got)
	}
	if !read {
		t.Error("an absent file is answered, not unread: nothing there is nothing to report")
	}

	// Unparseable, which is the same non-answer as unopenable and must not read
	// as a pass.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, read := hookMatchers(bad); read {
		t.Error("a file that would not parse was reported as read, so a host whose " +
			"settings are unreadable would pass this check")
	}
}
