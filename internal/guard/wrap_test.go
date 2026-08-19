package guard

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// These drive the hook through its real contract (a JSON payload on stdin, a
// JSON object on stdout) rather than calling decide() directly.

func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = original; _ = r.Close() }()
	go func() { _, _ = io.WriteString(w, input); _ = w.Close() }()
	fn()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()
	fn()
	_ = w.Close()
	os.Stdout = original
	return <-done
}

// hookOutput runs the guard the way the harness does.
func hookOutput(t *testing.T, payload string) map[string]any {
	t.Helper()
	stdout := captureStdout(t, func() {
		withStdin(t, payload, func() { Run(nil) })
	})
	if strings.TrimSpace(stdout) == "" {
		return nil
	}
	var out struct {
		Hook map[string]any `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", stdout, err)
	}
	return out.Hook
}

func bashPayload(t *testing.T, command string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
	hook := hookOutput(t, bashPayload(t, "ansible-playbook site.yml -vvv"))
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
	hook := hookOutput(t, bashPayload(t, original))
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

// The agent's shell persists between calls, so a subshell would lose every cd
// and export.
func TestTheCommandRunsInTheCallersOwnShell(t *testing.T) {
	command := wrappedCommand(t, hookOutput(t, bashPayload(t, "cd /var")))
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
		"sops -d secrets/vault.sops.yml",
		"cat ~/.ssh/id_rsa",
	} {
		hook := hookOutput(t, bashPayload(t, command))
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
		hook := hookOutput(t, bashPayload(t, tc.command))
		if rewritten := hook != nil; rewritten != tc.wantRewritten {
			t.Errorf("%q rewritten = %v, want %v", tc.command, rewritten, tc.wantRewritten)
		}
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
		hook := hookOutput(t, bashPayload(t, command))
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
