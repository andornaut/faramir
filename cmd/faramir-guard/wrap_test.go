package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// The hook's contract is a JSON payload on stdin and a JSON object on stdout,
// so the tests below drive it through those rather than calling decide().

func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = original; r.Close() }()
	go func() { _, _ = io.WriteString(w, input); w.Close() }()
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
	w.Close()
	os.Stdout = original
	return <-done
}

// hookOutput runs the guard the way the harness does: a payload on stdin, one
// JSON object on stdout.
func hookOutput(t *testing.T, payload string) map[string]any {
	t.Helper()
	stdout := captureStdout(t, func() {
		withStdin(t, payload, func() { run(nil) })
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

func bashPayload(command string) string {
	b, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": command},
	})
	return string(b)
}

// A command the deny list does not forbid still runs, but under the redactor:
// the deny list only covers what someone thought to name, and the command that
// leaks a credential is usually one nobody would have named.
func TestAnAllowedCommandIsRewrittenThroughTheRedactor(t *testing.T) {
	hook := hookOutput(t, bashPayload("ansible-playbook site.yml -vvv"))
	if hook == nil {
		t.Fatal("no hook output; the command was neither denied nor wrapped")
	}
	// A rewritten command cannot be allow-listed by any rule, so the hook has
	// to decide: claiming nothing would make every command prompt forever.
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
	// One simple command: the permission matcher will not match an allow rule
	// against a compound statement, so a rewrite containing one can never be
	// allow-listed and every command prompts forever.
	for _, compound := range []string{";", "{", "&&", "\n"} {
		if strings.Contains(command, compound) {
			t.Errorf("command = %q contains %q, which makes it un-allow-listable", command, compound)
		}
	}
}

// The command goes in verbatim: it runs in the agent's own shell, so there is
// no second parser to quote for, and quoting it would change what runs.
func TestTheCommandIsEmbeddedVerbatim(t *testing.T) {
	original := `echo "it's" $HOME 'and' a\ space  # trailing comment`
	hook := hookOutput(t, bashPayload(original))
	command := hook["updatedInput"].(map[string]any)["command"].(string)

	// Undo the shell's single-quote rule and compare with what went in: the
	// wrapper's eval re-parses this, so anything less exact changes what runs.
	i := strings.Index(command, "'")
	if i < 0 || !strings.HasSuffix(command, "'") {
		t.Fatalf("command = %q, want the original as one single-quoted word", command)
	}
	unquoted := strings.ReplaceAll(command[i+1:len(command)-1], `'\''`, "'")
	if unquoted != original {
		t.Errorf("unquoted = %q, want %q", unquoted, original)
	}
}

// The reason for the whole shape: the agent's shell persists between calls, so
// a wrapper that runs the command in a subshell loses every cd and export.
func TestTheCommandRunsInTheCallersOwnShell(t *testing.T) {
	command := hookOutput(t, bashPayload("cd /var"))["updatedInput"].(map[string]any)["command"].(string)
	for _, forbidden := range []string{"bash -lc", "bash -c", "| " + "faramir"} {
		if strings.Contains(command, forbidden) {
			t.Errorf("command = %q, must not run the command through %q", command, forbidden)
		}
	}
	if !strings.Contains(command, "wrap.sh 'cd /var'") {
		t.Errorf("command = %q, want the command handed to the sourced wrapper", command)
	}
}

// A denied command stays denied: the rewrite is for what the deny list lets
// through, not a replacement for it.
func TestADeniedCommandIsStillDenied(t *testing.T) {
	hook := hookOutput(t, bashPayload("sops -d secrets/vault.sops.yml"))
	if hook == nil {
		t.Fatal("no hook output for a denied command")
	}
	if hook["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hook["permissionDecision"])
	}
	if _, wrapped := hook["updatedInput"]; wrapped {
		t.Error("a denied command was also rewritten")
	}
}

// Wrapping the wrapper would nest a redactor inside a redactor on every run.
func TestAnAlreadyWrappedCommandIsLeftAlone(t *testing.T) {
	for _, command := range []string{
		"/usr/local/bin/faramir redact -- /bin/bash -lc 'echo hi'",
		"echo hi | faramir redact",
	} {
		if hook := hookOutput(t, bashPayload(command)); hook != nil {
			t.Errorf("%q produced %v, want no rewrite", command, hook)
		}
	}
}

// BashOutput reads the buffer of a command that is already running, so there is
// nothing to wrap and a rewrite would only corrupt the request.
func TestBashOutputIsNotRewritten(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"tool_name":  "BashOutput",
		"tool_input": map[string]any{"command": "echo hi"},
	})
	if hook := hookOutput(t, string(payload)); hook != nil {
		t.Errorf("BashOutput produced %v, want no rewrite", hook)
	}
}

// A rewrite replaces the tool input, so a field it does not hand back is a
// field the tool never sees: a dropped timeout or run_in_background changes how
// the command runs, not just how it reads.
func TestTheRewritePreservesTheOtherInputFields(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"tool_name": "Bash",
		"tool_input": map[string]any{
			"command":     "ls",
			"description": "list files",
			"timeout":     120000,
		},
	})
	updated := hookOutput(t, string(payload))["updatedInput"].(map[string]any)
	if updated["description"] != "list files" {
		t.Errorf("description = %v, want it carried through", updated["description"])
	}
	if updated["timeout"] == nil {
		t.Error("timeout was dropped by the rewrite")
	}
}

// Buffering output until the command ends is exactly wrong for a command whose
// output is read while it runs.
func TestBackgroundCommandsAreNotRewritten(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"tool_name": "Bash",
		"tool_input": map[string]any{
			"command":           "npm run dev",
			"run_in_background": true,
		},
	})
	if hook := hookOutput(t, string(payload)); hook != nil {
		t.Errorf("a run_in_background command was rewritten: %v", hook)
	}
	if hook := hookOutput(t, bashPayload("npm run dev &")); hook != nil {
		t.Errorf("a backgrounded command was rewritten: %v", hook)
	}
	// "&&" at the end is not backgrounding, it is an unterminated command.
	if hook := hookOutput(t, bashPayload("make build &")); hook != nil {
		t.Errorf("a backgrounded command was rewritten: %v", hook)
	}
}

// An incomplete command is quoted and handed to eval, which re-parses it in
// isolation: it fails the way it would have failed unwrapped, rather than
// taking the wrapper's own syntax down with it.
func TestAnIncompleteCommandIsStillWrappedSafely(t *testing.T) {
	for _, command := range []string{`echo hi \\`, "make build &&", "ls |", "echo hi;"} {
		hook := hookOutput(t, bashPayload(command))
		if hook == nil {
			t.Errorf("%q was not rewritten", command)
			continue
		}
		wrapped := hook["updatedInput"].(map[string]any)["command"].(string)
		if !strings.HasPrefix(wrapped, "source ") {
			t.Errorf("%q produced %q", command, wrapped)
		}
	}
}

// Mentioning the redactor is not using it.  Matching a bare space would let any
// command that merely names it skip redaction entirely.
func TestMentioningTheRedactorDoesNotSkipTheRewrite(t *testing.T) {
	for _, command := range []string{
		`echo "run faramir redact next"`,
		"grep -r 'faramir redact' docs/",
	} {
		if hook := hookOutput(t, bashPayload(command)); hook == nil {
			t.Errorf("%q skipped the rewrite by merely mentioning the redactor", command)
		}
	}
}

// An operator who would rather answer a prompt per command than delegate that
// to the deny list can have it.
func TestTheDecisionIsConfigurable(t *testing.T) {
	t.Setenv("FARAMIR_WRAP_DECISION", "ask")
	hook := hookOutput(t, bashPayload("ls -la"))
	if hook["permissionDecision"] != "ask" {
		t.Errorf("permissionDecision = %v, want ask", hook["permissionDecision"])
	}
	if _, rewritten := hook["updatedInput"]; !rewritten {
		t.Error("asking must still redact: the command was not rewritten")
	}
}

// The deny list runs first, so delegating the prompt to it does not widen what
// is reachable.
func TestADeniedCommandIsNeverAllowed(t *testing.T) {
	hook := hookOutput(t, bashPayload("cat ~/.ssh/id_rsa"))
	if hook["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hook["permissionDecision"])
	}
}
