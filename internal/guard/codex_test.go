package guard

import (
	"encoding/json"
	"strings"
	"testing"
)

// Codex reads Claude Code's hook contract, so what is pinned here is what it
// does not share: it runs commands through one tool rather than two, it writes
// files through a tool whose input is a patch rather than a command, and it has
// no rule file an install can put a path in, so the guard is the only thing
// refusing it one.

// codexCall is one Codex PreToolUse payload. cwd is the directory Codex says it
// is working in, which the guard resolves a relative path against.
func codexCall(t *testing.T, tool, cwd, command string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"tool_name":  tool,
		"cwd":        cwd,
		"tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The dialect, both halves. A rewrite that is not approved does not run, and a
// refusal in the wrong shape is ignored and the command runs unredacted.
func TestCodexIsAnsweredInTheHookDecisionShape(t *testing.T) {
	t.Run("a command is rewritten and approved", func(t *testing.T) {
		got := guardOutput(t, []string{"--host", "codex"},
			codexCall(t, "Bash", "/srv/app", "echo hi"))
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
		if command, _ := updated["command"].(string); !strings.Contains(command, "wrap.sh") {
			t.Errorf("command was not wrapped: %v", updated["command"])
		}
	})

	t.Run("a command the deny list names is refused", func(t *testing.T) {
		got := guardOutput(t, []string{"--host", "codex"},
			codexCall(t, "Bash", "/srv/app", "cat /etc/faramir/age.key"))
		out, ok := got["hookSpecificOutput"].(map[string]any)
		if !ok {
			t.Fatalf("no hookSpecificOutput: %v", got)
		}
		if out["permissionDecision"] != denyDecision {
			t.Errorf("permissionDecision = %v, want %s", out["permissionDecision"], denyDecision)
		}
	})
}

// apply_patch is the whole of how Codex writes a file, and its input carries
// the patch rather than a command. Read as a command it would be routed through
// the wrapper, and what came back would be a patch that no longer applies; left
// unread, an age key is replaced by a tool nothing is watching.
func TestAPatchIsCheckedByTheFilesItNamesAndNeverRewritten(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")

	const refused = "*** Begin Patch\n" +
		"*** Update File: /etc/faramir/age.key\n@@\n-old\n+new\n" +
		"*** End Patch"
	got := guardOutput(t, []string{"--host", "codex"},
		codexCall(t, applyPatchTool, "/srv/app", refused))
	out, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("a patch replacing the age key was not refused: %v", got)
	}
	if out["permissionDecision"] != denyDecision {
		t.Errorf("permissionDecision = %v, want %s", out["permissionDecision"], denyDecision)
	}
	if reason, _ := out["permissionDecisionReason"].(string); !strings.Contains(reason, "/etc/faramir/age.key") {
		t.Errorf("the refusal does not name the file it refused: %v", out["permissionDecisionReason"])
	}

	// An ordinary patch is left alone entirely: no decision, and above all no
	// updatedInput. Anything written back here replaces the patch.
	const ordinary = "*** Begin Patch\n*** Add File: notes.md\n+hello\n*** End Patch"
	if got := guardOutput(t, []string{"--host", "codex"},
		codexCall(t, applyPatchTool, "/srv/app", ordinary)); got != nil {
		t.Errorf("an ordinary patch was answered, so what applies is not what the model wrote: %v", got)
	}
}

// The patch is never scanned as a command line. It carries diff text, and a
// patch that adds documentation quoting `rm /etc/faramir/config.toml` is not a
// command to remove it: read as one, editing the docs is refused for what the
// docs say.
func TestAPatchBodyIsNotReadAsACommand(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")

	const patch = "*** Begin Patch\n*** Update File: docs/operating.md\n@@\n" +
		"+Never run `rm /etc/faramir/config.toml`.\n*** End Patch"
	if got := guardOutput(t, []string{"--host", "codex"},
		codexCall(t, applyPatchTool, "/srv/app", patch)); got != nil {
		t.Errorf("a patch was refused for the text inside it rather than the file it "+
			"writes: %v", got)
	}
}

// Every header, and every verb the grammar has. A patch is a list of edits, and
// one that adds a README and deletes an age key is refused for the second; a
// verb this does not read is a way past the list.
func TestEveryPatchHeaderIsRead(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")

	for _, verb := range []string{"Add File", "Update File", "Delete File", "Move to"} {
		patch := "*** Begin Patch\n*** Add File: README.md\n+hi\n" +
			"*** " + verb + ": /etc/faramir/age.key\n*** End Patch"
		if _, refused := refusedPatchPath("", patch); !refused {
			t.Errorf("a patch whose %q header names the age key was not refused", verb)
		}
	}
	// And a patch touching neither is not refused for having a header at all.
	if _, refused := refusedPatchPath("",
		"*** Begin Patch\n*** Add File: README.md\n+hi\n*** End Patch"); refused {
		t.Error("an ordinary patch was refused")
	}
}

// A patch names a file relative to the tree Codex is working in, and the rules
// name absolute ones. Codex sends that directory in the payload, so the guard
// takes its word for it rather than guessing from its own: a hook runs as a
// program of its own and is started wherever the host pleases.
func TestAPatchPathIsResolvedAgainstTheDirectoryCodexNames(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")

	// Asked as written it is refused by nothing, so what follows is the
	// resolution rather than a rule that covered the relative form already.
	if _, refused := refusedPatchPath("",
		"*** Begin Patch\n*** Update File: faramir/age.key\n*** End Patch"); refused {
		t.Fatal("the relative form is refused unresolved, so this asserts nothing")
	}

	got := guardOutput(t, []string{"--host", "codex"}, codexCall(t, applyPatchTool, "/etc",
		"*** Begin Patch\n*** Update File: faramir/age.key\n@@\n+x\n*** End Patch"))
	if got == nil {
		t.Fatal("a patch writing into this install's own directory was not refused")
	}
}

// Codex runs no BashOutput and reads a file by running one of the shell's own
// readers, so one tool is the whole of what it runs commands through. A second
// name here is a tool the rewrite would fire on that does not exist.
func TestCodexRunsCommandsThroughOneTool(t *testing.T) {
	h := hosts["codex"]
	if len(h.shellTools) != 1 || h.shellTools[0] != bashTool {
		t.Errorf("shellTools = %v, want [%s]", h.shellTools, bashTool)
	}
	if h.wrapTool != bashTool {
		t.Errorf("wrapTool = %q, want %q", h.wrapTool, bashTool)
	}
	// And the patch tool is not one of them: named as a shell tool it would be
	// wrapped.
	if h.handles(applyPatchTool) {
		t.Errorf("%s is treated as a tool that runs commands", applyPatchTool)
	}
}

// THE REFUSAL: an envelope that is not where the guard reads it is denied
// rather than allowed. This is the only tool Codex writes files with and this
// branch is the only thing refusing it a path, so a key that moved would leave
// every patch unexamined and say nothing.
func TestAPatchWithNoReadableEnvelopeIsRefused(t *testing.T) {
	for _, name := range []string{"an empty command", "whitespace only"} {
		command := ""
		if name == "whitespace only" {
			command = "  \n\t "
		}
		got := guardOutput(t, []string{"--host", "codex"},
			codexCall(t, applyPatchTool, "/srv/app", command))
		out, ok := got["hookSpecificOutput"].(map[string]any)
		if !ok {
			t.Fatalf("%s: the patch was allowed, so a moved envelope key runs "+
				"unexamined: %v", name, got)
		}
		if out["permissionDecision"] != denyDecision {
			t.Errorf("%s: permissionDecision = %v, want %s",
				name, out["permissionDecision"], denyDecision)
		}
		reason, _ := out["permissionDecisionReason"].(string)
		if !strings.Contains(reason, "could not read") {
			t.Errorf("%s: the refusal does not say the patch was unreadable: %v",
				name, reason)
		}
	}
}

// A patch written with CRLF names the same file, and Go's `$` in multi-line
// mode matches before the newline without consuming the carriage return. Left
// on the capture it is part of the path, and a path rule is bounded at its
// right edge, so the header would name the age key and match no rule about it.
func TestAPatchHeaderIsReadWithEitherLineEnding(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")

	const crlf = "*** Begin Patch\r\n*** Update File: /etc/faramir/age.key\r\n@@\r\n+x\r\n*** End Patch\r\n"
	path, refused := refusedPatchPath("", crlf)
	if !refused {
		t.Fatal("a CRLF patch replacing the age key was not refused")
	}
	if strings.ContainsAny(path, "\r\n") {
		t.Errorf("the path carries its line ending: %q", path)
	}
}

// The patch tool is invocable from a shell, and the documented spelling puts
// the envelope in a quoted heredoc. A quoted heredoc body is data rather than
// commands, so the deny list never sees the headers: every other heredoc write
// names its file on the opening line, and this is the one that does not.
func TestAPatchRunAsAShellCommandIsCheckedByItsHeaders(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	t.Setenv("FARAMIR_CONFIG", "/etc/faramir/config.toml")

	refused := applyPatchTool + " <<'PATCH'\n*** Begin Patch\n" +
		"*** Update File: /etc/faramir/age.key\n@@\n+x\n*** End Patch\nPATCH"
	got := guardOutput(t, []string{"--host", "codex"}, codexCall(t, "Bash", "/srv/app", refused))
	out, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("a patch heredoc replacing the age key was allowed: %v", got)
	}
	if out["permissionDecision"] != denyDecision {
		t.Errorf("permissionDecision = %v, want %s", out["permissionDecision"], denyDecision)
	}

	// Only where a segment runs the tool. A heredoc that writes documentation
	// quoting a header is ordinary work, and refusing it would name the quoted
	// line as though the file were being written.
	quoted := "tee doc <<'PATCH'\n*** Begin Patch\n" +
		"*** Update File: /srv/app/notes.md\n*** End Patch\nPATCH"
	if _, denied := refusedPatchCommand(hosts["codex"], "", quoted); denied {
		t.Error("a heredoc that quotes a header was refused, so writing about the " +
			"patch format is refused as writing the file")
	}
	// And the tool named as an argument is not the tool being run.
	named := "echo " + applyPatchTool + " <<'PATCH'\n*** Add File: /etc/faramir/x\n*** End Patch\nPATCH"
	if _, denied := refusedPatchCommand(hosts["codex"], "", named); denied {
		t.Error("the tool named as an argument was read as the tool being run")
	}
}
