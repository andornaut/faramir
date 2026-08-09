package guard

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// These drive the hook through its real contract -- a JSON payload on stdin, a
// JSON object on stdout -- rather than calling decide() directly.

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

func bashPayload(command string) string {
	b, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": command},
	})
	return string(b)
}

func TestAnAllowedCommandIsRewrittenThroughTheRedactor(t *testing.T) {
	hook := hookOutput(t, bashPayload("ansible-playbook site.yml -vvv"))
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
	// The permission matcher will not match an allow rule against a compound
	// statement, so a rewrite containing one can never be allow-listed.
	for _, compound := range []string{";", "{", "&&", "\n"} {
		if strings.Contains(command, compound) {
			t.Errorf("command = %q contains %q, which makes it un-allow-listable", command, compound)
		}
	}
}

func TestTheCommandIsEmbeddedVerbatim(t *testing.T) {
	original := `echo "it's" $HOME 'and' a\ space  # trailing comment`
	hook := hookOutput(t, bashPayload(original))
	command := hook["updatedInput"].(map[string]any)["command"].(string)

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

// Only the form the rewrite emits is left alone; everything else below runs
// some part of itself uncovered if mistaken for one.
func TestOnlyTheEmittedFormIsLeftAlone(t *testing.T) {
	for command, wantRewritten := range map[string]bool{
		"source " + wrapScript() + " 'ls -la'": false,
		". " + wrapScript() + " 'ls -la'":      false,
		// A pipe carries stdout, leaving stderr unredacted.
		"echo hi | faramir redact":                         true,
		"/usr/local/bin/faramir redact -- /bin/bash -lc x": true,
		"faramir redact":                                   true,
		// The redactor covers its own element, not what is chained after it.
		"faramir redact -- true; ./leak.sh":     true,
		"faramir redact -- true && ./leak.sh":   true,
		"echo hi | faramir redact || ./leak.sh": true,
		"faramir redact -- true\n./leak.sh":     true,
	} {
		hook := hookOutput(t, bashPayload(command))
		if rewritten := hook != nil; rewritten != wantRewritten {
			t.Errorf("%q rewritten = %v, want %v", command, rewritten, wantRewritten)
		}
	}
}

// BashOutput reads an already-running command's buffer, so there is nothing to
// wrap.
func TestBashOutputIsNotRewritten(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"tool_name":  "BashOutput",
		"tool_input": map[string]any{"command": "echo hi"},
	})
	if hook := hookOutput(t, string(payload)); hook != nil {
		t.Errorf("BashOutput produced %v, want no rewrite", hook)
	}
}

// A rewrite replaces the tool input, so a field it does not hand back is one
// the tool never sees.
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

// Buffering is wrong for a command whose output is read while it runs.
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

// eval re-parses the quoted command in isolation, so it fails the way it would
// have failed unwrapped rather than breaking the wrapper's own syntax.
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

// Mentioning the redactor is not using it.
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

// The decision is not configurable: "ask" would prompt on every command with
// no rule able to pre-approve one.
func TestAnAllowedCommandIsAlwaysAllowed(t *testing.T) {
	t.Setenv("FARAMIR_WRAP_DECISION", "ask")
	hook := hookOutput(t, bashPayload("ls -la"))
	if hook["permissionDecision"] != "allow" {
		t.Errorf("permissionDecision = %v, want allow", hook["permissionDecision"])
	}
	if _, rewritten := hook["updatedInput"]; !rewritten {
		t.Error("the command was not rewritten, so its output is not redacted")
	}
}

func TestADeniedCommandIsNeverAllowed(t *testing.T) {
	hook := hookOutput(t, bashPayload("cat ~/.ssh/id_rsa"))
	if hook["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hook["permissionDecision"])
	}
}
