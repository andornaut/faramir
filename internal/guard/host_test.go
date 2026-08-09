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
	// Closed before reading; the guard writes far less than a pipe buffer.
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

// The hosts disagree about where a refusal goes and what an approval is, and
// the wrong dialect fails open, so each shape is pinned.
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
		// updatedInput replaces the tool input, so every field comes back.
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
		// There is no allow to return on this host.
		if _, wrong := out["permissionDecision"]; wrong {
			t.Error("gemini was sent a permissionDecision")
		}
	})

	// The plugin applies the decision itself, so the reply is faramir's own
	// shape; both halves are pinned because the plugin is a separate file.
	t.Run("the plugin hosts are answered in faramir's own shape", func(t *testing.T) {
		for _, host := range []string{"opencode", "kilocode"} {
			got := guardOutput(t, []string{"--host", host},
				`{"tool_name":"bash","tool_input":{"command":"echo hi","description":"greet"}}`)
			if got["decision"] != "rewrite" {
				t.Errorf("%s: decision = %v, want rewrite", host, got["decision"])
			}
			updated, ok := got["tool_input"].(map[string]any)
			if !ok {
				t.Fatalf("%s: no tool_input: %v", host, got)
			}
			if !strings.Contains(updated["command"].(string), "wrap.sh") {
				t.Errorf("%s: command was not wrapped: %v", host, updated["command"])
			}
			// Assigned over the arguments the model sent.
			if updated["description"] != "greet" {
				t.Errorf("%s: description was dropped: %v", host, updated)
			}
			// Neither agent reads a hook document.
			if _, wrong := got["hookSpecificOutput"]; wrong {
				t.Errorf("%s: was sent a hook document", host)
			}
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

		for _, host := range []string{"opencode", "kilocode"} {
			plugin := guardOutput(t, []string{"--host", host},
				strings.Replace(denied, "%s", "bash", 1))
			if plugin["decision"] != "deny" {
				t.Errorf("%s: decision = %v, want deny", host, plugin["decision"])
			}
			// The plugin throws this text, and it is all the model is told.
			if reason, _ := plugin["reason"].(string); !strings.Contains(reason, "faramir_run") {
				t.Errorf("%s: deny does not name the tool to use instead: %v", host, plugin["reason"])
			}
		}
	})
}

// A tool that does not run a shell command has no output to redact, and the
// name differs per host.
func TestHostHandlesOnlyItsOwnShellTool(t *testing.T) {
	if got := guardOutput(t, []string{"--host", "gemini"},
		`{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`); got != nil {
		t.Errorf("gemini guard acted on Claude's tool name: %v", got)
	}
	if got := guardOutput(t, nil,
		`{"tool_name":"run_shell_command","tool_input":{"command":"echo hi"}}`); got != nil {
		t.Errorf("claude guard acted on Gemini's tool name: %v", got)
	}
	// A plugin sees every tool call, so this arises on every read and edit.
	if got := guardOutput(t, []string{"--host", "opencode"},
		`{"tool_name":"read","tool_input":{"filePath":"/etc/hosts"}}`); got != nil {
		t.Errorf("opencode guard acted on a tool that runs nothing: %v", got)
	}
}

// Refused before stdin is read; a fallback would answer in a dialect the agent
// ignores.
func TestUnknownHostIsRefused(t *testing.T) {
	if code := Run([]string{"--host", "nosuchagent"}); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}
