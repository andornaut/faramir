package guard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// guardOutput runs the guard against one payload and returns what it wrote.
func guardOutput(t *testing.T, args []string, payload string) map[string]any {
	t.Helper()
	stdin, stdout := os.Stdin, os.Stdout
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin, os.Stdout = inR, outW
	t.Cleanup(func() { os.Stdin, os.Stdout = stdin, stdout })

	go func() { _, _ = inW.WriteString(payload); _ = inW.Close() }()
	code := Run(args)
	// Closed before reading: the guard writes far less than a pipe buffer, so
	// this cannot deadlock, and an open write end would make the read block.
	_ = outW.Close()
	buf := make([]byte, 1<<16)
	n, _ := outR.Read(buf)
	_ = outR.Close()
	if code != 0 {
		t.Fatalf("guard exited %d", code)
	}
	if n == 0 {
		return nil
	}
	var got map[string]any
	if err := json.Unmarshal(buf[:n], &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf[:n])
	}
	return got
}

// The two hosts disagree about where a refusal goes and what an approval is.
// Answering in the wrong dialect fails open, because a document the agent does
// not understand is a command it runs unredacted, so each shape is pinned.
func TestHostDialects(t *testing.T) {
	t.Run("claude rewrites through updatedInput and approves explicitly", func(t *testing.T) {
		got := guardOutput(t, nil,
			`{"tool_name":"Bash","tool_input":{"command":"echo hi","timeout":5}}`)
		out, ok := got["hookSpecificOutput"].(map[string]any)
		if !ok {
			t.Fatalf("no hookSpecificOutput: %v", got)
		}
		if out["permissionDecision"] != "allow" {
			t.Errorf("permissionDecision = %v, want allow", out["permissionDecision"])
		}
		updated, ok := out["updatedInput"].(map[string]any)
		if !ok {
			t.Fatalf("no updatedInput: %v", out)
		}
		if !strings.Contains(updated["command"].(string), "wrap.sh") {
			t.Errorf("command was not wrapped: %v", updated["command"])
		}
		// Every field the payload carried comes back: updatedInput replaces the
		// tool input, so one dropped here is one the tool never sees.
		if updated["timeout"] == nil {
			t.Error("timeout was dropped from updatedInput")
		}
	})

	t.Run("gemini rewrites through tool_input and approves nothing", func(t *testing.T) {
		got := guardOutput(t, []string{"--host", "gemini"},
			`{"tool_name":"run_shell_command","tool_input":{"command":"echo hi"}}`)
		out, ok := got["hookSpecificOutput"].(map[string]any)
		if !ok {
			t.Fatalf("no hookSpecificOutput: %v", got)
		}
		if _, wrong := out["updatedInput"]; wrong {
			t.Error("gemini was sent Claude's updatedInput")
		}
		updated, ok := out["tool_input"].(map[string]any)
		if !ok {
			t.Fatalf("no tool_input: %v", out)
		}
		if !strings.Contains(updated["command"].(string), "wrap.sh") {
			t.Errorf("command was not wrapped: %v", updated["command"])
		}
		// There is no allow to return, so claiming one would be inventing a
		// field the host does not read.
		if _, wrong := out["permissionDecision"]; wrong {
			t.Error("gemini was sent a permissionDecision")
		}
	})

	t.Run("a refusal reaches each host where it reads one", func(t *testing.T) {
		denied := `{"tool_name":"%s","tool_input":{"command":"cat ~/.config/sops/age/keys.txt"}}`

		claude := guardOutput(t, nil, strings.Replace(denied, "%s", "Bash", 1))
		out := claude["hookSpecificOutput"].(map[string]any)
		if out["permissionDecision"] != "deny" {
			t.Errorf("claude: permissionDecision = %v, want deny", out["permissionDecision"])
		}

		gemini := guardOutput(t, []string{"--host=gemini"},
			strings.Replace(denied, "%s", "run_shell_command", 1))
		if gemini["decision"] != "deny" {
			t.Errorf("gemini: decision = %v, want deny at the top level", gemini["decision"])
		}
		if gemini["reason"] == nil || gemini["reason"] == "" {
			t.Error("gemini: deny carried no reason, which it requires")
		}
	})
}

// A tool that does not run a shell command has no output to redact, and the
// name differs per host: Claude's Bash payload reaching a Gemini-registered
// guard is a misregistration, not something to rewrite.
func TestHostHandlesOnlyItsOwnShellTool(t *testing.T) {
	if got := guardOutput(t, []string{"--host", "gemini"},
		`{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`); got != nil {
		t.Errorf("gemini guard acted on Claude's tool name: %v", got)
	}
	if got := guardOutput(t, nil,
		`{"tool_name":"run_shell_command","tool_input":{"command":"echo hi"}}`); got != nil {
		t.Errorf("claude guard acted on Gemini's tool name: %v", got)
	}
}

// An unknown host is refused before stdin is read. Falling back would answer in
// a dialect the agent ignores, which is a command running unredacted.
func TestUnknownHostIsRefused(t *testing.T) {
	if code := Run([]string{"--host", "nosuchagent"}); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}
