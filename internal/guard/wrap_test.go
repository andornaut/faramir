package guard

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These drive the hook through its real contract (a JSON payload on stdin, a
// JSON object on stdout) rather than calling decide() directly; the pipe
// harness is host_test's guardOutput.

// hookOutput runs the guard as Claude Code's hook and unwraps its envelope.
func hookOutput(t *testing.T, payload string) map[string]any {
	t.Helper()
	got := guardOutput(t, nil, payload)
	hook, _ := got["hookSpecificOutput"].(map[string]any)
	return hook
}

// updatedInput is the tool input a rewrite handed back, and wrappedCommand the
// command inside it. Checked rather than asserted: what these tests are about
// is the shape of that answer, so a hook that returned another one has to fail
// as a test rather than as a panic in the middle of one.
func updatedInput(t *testing.T, hook map[string]any) map[string]any {
	t.Helper()
	updated, ok := hook["updatedInput"].(map[string]any)
	if !ok {
		t.Fatalf("no updatedInput: %v", hook)
	}
	return updated
}

func wrappedCommand(t *testing.T, hook map[string]any) string {
	t.Helper()
	updated := updatedInput(t, hook)
	command, ok := updated["command"].(string)
	if !ok {
		t.Fatalf("no command in updatedInput: %v", updated)
	}
	return command
}

func TestAnAllowedCommandIsRewrittenThroughTheRedactor(t *testing.T) {
	hook := hookOutput(t, bashCall(t, "ansible-playbook site.yml -vvv"))
	if hook == nil {
		t.Fatal("no hook output; the command was neither denied nor wrapped")
	}
	// A rewritten command matches no allow rule, so the hook has to decide.
	if hook["permissionDecision"] != "allow" {
		t.Errorf("permissionDecision = %v, want allow", hook["permissionDecision"])
	}
	updated, ok := hook["updatedInput"].(map[string]any)
	if !ok {
		t.Fatalf("no updatedInput in %v", hook)
	}
	command, _ := updated["command"].(string)
	if !strings.HasPrefix(command, "source ") {
		t.Errorf("command = %q, want it to source the wrapper", command)
	}
	if !strings.Contains(command, "ansible-playbook site.yml -vvv") {
		t.Errorf("command = %q, want the original preserved inside", command)
	}
	// The rewrite stays one simple command: isWrapped tests for it by prefix, so a
	// compound statement would break idempotence and chain past the redirection.
	for _, compound := range []string{";", "{", "&&", "\n"} {
		if strings.Contains(command, compound) {
			t.Errorf("command = %q contains %q, which makes it un-allow-listable", command, compound)
		}
	}
}

func TestTheCommandIsEmbeddedVerbatim(t *testing.T) {
	original := `echo "it's" $HOME 'and' a\ space  # trailing comment`
	hook := hookOutput(t, bashCall(t, original))
	command := wrappedCommand(t, hook)

	// Undo the shell's single-quote rule and compare with what went in.
	i := strings.Index(command, "'")
	if i < 0 || !strings.HasSuffix(command, "'") {
		t.Fatalf("command = %q, want the original as one single-quoted word", command)
	}
	unquoted := strings.ReplaceAll(command[i+1:len(command)-1], `'\''`, "'")
	if unquoted != original {
		t.Errorf("unquoted = %q, want %q", unquoted, original)
	}
}

// And the quoting is put to the thing that will parse it. Undoing it with this
// test's own inverse passes just as well when nothing was escaped at all: the
// naive extraction above recovers the original either way. A shell does not.
// An unescaped quote ends the word early, and what follows is parsed as shell
// rather than carried as text.
func TestTheQuotedCommandIsOneWordToARealShell(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh to parse the quoting with")
	}
	for _, original := range []string{
		`echo "it's" $HOME 'and' a\ space  # trailing comment`,
		"a'b",
		"'",
		// What the escaping is for: unescaped, the quote ends the word and the
		// rest is a command of its own.
		"'; echo broken-out; :'",
	} {
		got, rewritten := wrap(hosts["claude"], original, bashInput())
		if !rewritten {
			t.Fatalf("did not wrap %q", original)
		}
		arg, ok := strings.CutPrefix(got, "source "+wrapScript()+" ")
		if !ok {
			t.Fatalf("command = %q, want it to source the wrapper", got)
		}
		// printf writes its one argument and nothing else, so a word that ended
		// early comes back as a parse error, as another command's output, or as
		// the arguments concatenated: none of them is the string that went in.
		out, err := exec.Command("/bin/sh", "-c", "printf %s "+arg).CombinedOutput()
		if err != nil {
			t.Errorf("a shell would not parse %q: %v (%s)", got, err, out)
			continue
		}
		if string(out) != original {
			t.Errorf("the shell reads the wrapped form of %q as %q", original, out)
		}
	}
}

// The agent's shell persists between calls, so a subshell would lose every cd
// and export.
func TestTheCommandRunsInTheCallersOwnShell(t *testing.T) {
	command := wrappedCommand(t, hookOutput(t, bashCall(t, "cd /var")))
	for _, forbidden := range []string{"bash -lc", "bash -c", "| " + "faramir"} {
		if strings.Contains(command, forbidden) {
			t.Errorf("command = %q, must not run the command through %q", command, forbidden)
		}
	}
	if !strings.Contains(command, "wrap.sh 'cd /var'") {
		t.Errorf("command = %q, want the command handed to the sourced wrapper", command)
	}
}

func TestADeniedCommandIsStillDenied(t *testing.T) {
	for _, command := range []string{
		"cat /etc/faramir/age.key",
	} {
		hook := hookOutput(t, bashCall(t, command))
		if hook == nil {
			t.Fatalf("no hook output for %q", command)
		}
		if hook["permissionDecision"] != "deny" {
			t.Errorf("%q: permissionDecision = %v, want deny", command, hook["permissionDecision"])
		}
		if _, wrapped := hook["updatedInput"]; wrapped {
			t.Errorf("%q was denied and also rewritten", command)
		}
	}
}

// Only the form the rewrite emits is left alone; everything else below runs
// some part of itself uncovered if mistaken for one, its output reaching the
// transcript unredacted.
func TestOnlyTheEmittedFormIsLeftAlone(t *testing.T) {
	for _, tc := range []struct {
		command       string
		wantRewritten bool
	}{
		{"source " + wrapScript() + " 'ls -la'", false},
		{". " + wrapScript() + " 'ls -la'", false},
		// Naming the wrapper is not using it.
		{"cat " + wrapScript(), true},
		{"echo " + wrapScript() + "; ./leak.sh", true},
		{"cd /tmp && source " + wrapScript() + " x", true},
		// A pipe carries stdout, leaving stderr unredacted.
		{"echo hi | faramir redact", true},
		{"/usr/local/bin/faramir redact -- /bin/bash -lc x", true},
		{"faramir redact", true},
		// The redactor covers its own element, not what is chained after it.
		{"faramir redact -- true; ./leak.sh", true},
		{"faramir redact -- true && ./leak.sh", true},
		{"echo hi | faramir redact || ./leak.sh", true},
		{"faramir redact -- true & ./leak.sh", true},
		{"faramir redact -- true\n./leak.sh", true},
		// Merely naming it, which is what documentation and a grep do.
		{`echo "run faramir redact next"`, true},
		{"grep -r 'faramir redact' docs/", true},
	} {
		hook := hookOutput(t, bashCall(t, tc.command))
		if rewritten := hook != nil; rewritten != tc.wantRewritten {
			t.Errorf("%q rewritten = %v, want %v", tc.command, rewritten, tc.wantRewritten)
		}
	}
}

// The shape BashOutput actually arrives in: it names the shell it reads from
// and carries no command at all. The host lists it among the tools it runs
// commands through so the wrap step can skip it deliberately, and a shell tool
// with no command is otherwise the shape-changed case this denies. Denying it
// would stop the model reading anything a backgrounded command printed, which
// the redactor has already been through.
func TestBashOutputCarryingNoCommandIsLeftAlone(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"tool_name":  "BashOutput",
		"tool_input": map[string]any{"bash_id": "bash_1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hook := hookOutput(t, string(payload)); hook != nil {
		t.Errorf("BashOutput produced %v, want nothing said", hook)
	}
}

// BashOutput reads an already-running command's buffer, so there is nothing to
// wrap.
func TestBashOutputIsNotRewritten(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"tool_name":  "BashOutput",
		"tool_input": map[string]any{"command": "echo hi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hook := hookOutput(t, string(payload)); hook != nil {
		t.Errorf("BashOutput produced %v, want no rewrite", hook)
	}
}

// A rewrite replaces the tool input, so a field it does not hand back is one
// the tool never sees.
func TestTheRewritePreservesTheOtherInputFields(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash",
		"tool_input": map[string]any{
			"command":     "ls",
			"description": "list files",
			"timeout":     120000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated := updatedInput(t, hookOutput(t, string(payload)))
	if updated["description"] != "list files" {
		t.Errorf("description = %v, want it carried through", updated["description"])
	}
	if updated["timeout"] == nil {
		t.Error("timeout was dropped by the rewrite")
	}
}

// run_in_background is the tool's own flag rather than shell syntax, so it is
// the one backgrounding case the rewrite cannot see in the command text. The
// trailing-"&" forms are TestABackgroundedCommandIsWrappedToStreamHoweverItEnds.
func TestARunInBackgroundCallIsStreamedNotCaptured(t *testing.T) {
	// The host backgrounds this one and reads its output later through
	// BashOutput, so the command is streamed through the redactor: no trailing
	// "&" of its own (the host adds the backgrounding), and BashOutput then sees
	// what the redactor already passed.
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash",
		"tool_input": map[string]any{
			"command":           "npm run dev",
			"run_in_background": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hook := hookOutput(t, string(payload))
	if hook == nil {
		t.Fatal("a run_in_background command was not rewritten")
	}
	updated, _ := hook["updatedInput"].(map[string]any)
	got, _ := updated["command"].(string)
	if !strings.Contains(got, "--stream ") {
		t.Errorf("run_in_background command not streamed: %q", got)
	}
	if strings.HasSuffix(got, " &") {
		t.Errorf("run_in_background command carried its own backgrounding: %q", got)
	}
}

// eval re-parses the quoted command in isolation, so it fails the way it would
// have failed unwrapped rather than breaking the wrapper's own syntax.
func TestAnIncompleteCommandIsStillWrappedSafely(t *testing.T) {
	for _, command := range []string{`echo hi \\`, "make build &&", "ls |", "echo hi;"} {
		hook := hookOutput(t, bashCall(t, command))
		if hook == nil {
			t.Errorf("%q was not rewritten", command)
			continue
		}
		wrapped := wrappedCommand(t, hook)
		if !strings.HasPrefix(wrapped, "source ") {
			t.Errorf("%q produced %q", command, wrapped)
		}
	}
}
