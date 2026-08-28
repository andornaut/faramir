package guard

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"
)

// Antigravity's hook contract differs from Claude Code's in three places, and
// each of them fails silently: a payload read wrong carries no command and the
// call goes through unwrapped, a reply in the wrong shape is ignored and the
// original command runs, and a rewrite that hands back every argument writes a
// second copy of them into a merge.

// The command is under toolCall.args.CommandLine rather than beside the tool
// name. Read from the wrong place it is empty, which for the tool this host
// wraps is a refusal rather than a pass, so the failure is loud; read from the
// right one it is the command the agent typed.
func TestTheCommandIsReadFromTheToolCallsArguments(t *testing.T) {
	const command = "echo hello"
	p, err := decodeToolCall([]byte(`{"toolCall":{"name":"run_command","args":{` +
		`"CommandLine":"echo hello","Cwd":"/srv","WaitMsBeforeAsync":5000}},"stepIdx":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolName != "run_command" {
		t.Errorf("tool name = %q, want %q", p.ToolName, "run_command")
	}
	if got := commandOf(p); got != command {
		t.Errorf("command = %q, want %q", got, command)
	}
	// The rest of the arguments are kept: Cwd is the directory the wrapper has
	// to run in, and a rewrite that dropped it would move the command.
	if p.RawInput["Cwd"] != "/srv" {
		t.Errorf("Cwd was lost: %v", p.RawInput)
	}
}

// A tool carrying no command is left alone rather than refused, for every tool
// but the one this host runs commands through. Antigravity's file and browser
// tools arrive at a hook registered for all of them.
func TestAToolThatRunsNoCommandIsLeftAlone(t *testing.T) {
	p, err := decodeToolCall([]byte(`{"toolCall":{"name":"read_file","args":{"Path":"/tmp/x"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if hosts["agy"].handles(p.ToolName) {
		t.Errorf("read_file is treated as a tool that runs commands, so a hook "+
			"registered for every tool would answer for it: %q", p.ToolName)
	}
}

// A rewrite is a shallow merge into the call's own arguments, so it hands back
// the command and nothing else. Handing back Cwd and the rest would write a
// second copy of arguments the call already carries.
func TestARewriteHandsBackTheCommandAlone(t *testing.T) {
	for _, name := range []string{"agy", "antigravity"} {
		h := hosts[name]
		if !h.mergesInput {
			t.Errorf("%s does not merge its input, so a rewrite replaces the "+
				"call's arguments with only the command", name)
			continue
		}
		if h.commandField() != "CommandLine" {
			t.Errorf("%s writes the command to %q, which is not the key the tool "+
				"reads it from", name, h.commandField())
		}
		doc := h.rewrite(map[string]any{h.commandField(): "source /x/wrap.sh 'ls'"})
		if doc["decision"] != "allow" {
			t.Errorf("%s: decision = %v, want allow: a rewrite that does not "+
				"approve is a command with no rule able to permit it", name, doc["decision"])
		}
		overwrite, ok := doc["overwrite"].(map[string]any)
		if !ok {
			t.Fatalf("%s: the rewrite is not under \"overwrite\", so it is ignored "+
				"and the original command runs: %v", name, doc)
		}
		if len(overwrite) != 1 || overwrite["CommandLine"] != "source /x/wrap.sh 'ls'" {
			t.Errorf("%s: overwrite = %v, want the command alone", name, overwrite)
		}
	}
}

// A refusal is the decision and the reason, which is what reaches the model.
func TestARefusalNamesItselfInTheHostsOwnShape(t *testing.T) {
	doc := hosts["agy"].deny("because")
	if doc["decision"] != "deny" || doc["reason"] != "because" {
		t.Errorf("deny = %v, want a decision and a reason", doc)
	}
}

// End to end through Run's own decoding, which is where a host that named no
// decoder would fall back to the wrong shape and read no command at all.
func TestTheWholeExchangeRewritesTheCommandThatRuns(t *testing.T) {
	out := runGuard(t, "agy", `{"toolCall":{"name":"run_command","args":{`+
		`"CommandLine":"echo hello","Cwd":"/srv"}},"stepIdx":1}`)
	overwrite, ok := out["overwrite"].(map[string]any)
	if !ok {
		t.Fatalf("no overwrite in the reply: %v", out)
	}
	command, _ := overwrite["CommandLine"].(string)
	if !strings.Contains(command, wrapScript()) {
		t.Errorf("the command was not routed through the wrapper: %q", command)
	}
	if !strings.Contains(command, "'echo hello'") {
		t.Errorf("the command was not carried into the wrapper: %q", command)
	}
}

// The two names speak one dialect, so an enrolment naming either writes a
// registration the other would have written. A divergence has somewhere to go
// and must not arrive by accident.
func TestTheFamilySpeaksOneDialect(t *testing.T) {
	first := runGuard(t, "agy", `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`)
	second := runGuard(t, "antigravity", `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`)
	want, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Errorf("the two names answer differently:\n%s\n%s", want, got)
	}
}

// fmtPathAdvice is the refusal a denied path gets, as Run renders it.
func fmtPathAdvice(path string) string { return fmt.Sprintf(pathAdvice, path) }

// runGuard drives one payload through the host's own decoding and returns the
// decoded reply. Empty where the guard answered nothing, which is a call left
// alone.
func runGuard(t *testing.T, host, payload string) map[string]any {
	t.Helper()
	h, err := lookupHost(host)
	if err != nil {
		t.Fatal(err)
	}
	decode := h.decode
	if decode == nil {
		decode = decodeToolInput
	}
	p, err := decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	command := commandOf(p)
	if command == "" && h.refusesPaths {
		if path, denied := refusedPath(p.RawInput); denied {
			_ = path
			return h.deny(fmtPathAdvice(path))
		}
	}
	if !h.handles(p.ToolName) {
		return nil
	}
	if pattern, denied := decide(command); denied {
		return h.deny(pattern)
	}
	wrapped, ok := wrap(h, command, p)
	if !ok {
		return nil
	}
	updated := map[string]any{}
	if !h.mergesInput {
		maps.Copy(updated, p.RawInput)
	}
	updated[h.commandField()] = wrapped
	return h.rewrite(updated)
}

// The IDE half of this family keeps its permission lists as its own state, so
// no file an install writes refuses its file tools. The hook is registered for
// every tool, so a read is refused here or nowhere.
//
// The set is the command deny list, asked about a read of the path, so an
// operator's own declared files and this install's directories are covered by
// the list that already names them rather than by a second one that drifts.
func TestAFileToolIsRefusedThePathsTheDenyListNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  string
		block bool
	}{
		{"this install's own key", `{"Path":"/etc/faramir/age.key"}`, true},
		{"its libexec, under a differently named argument",
			`{"AbsolutePath":"/usr/local/libexec/faramir/deny-patterns.txt"}`, true},
		{"a path among several, in a tool with no fixed schema",
			`{"Paths":["/srv/README.md","/etc/faramir/config.toml"]}`, true},
		{"an ordinary source file", `{"Path":"/srv/app/main.go"}`, false},
		// A refs file names secrets and holds none.
		{"a file of refs, which is meant to be read", `{"Path":"/srv/app/faramir.env"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := runGuard(t, "antigravity",
				`{"toolCall":{"name":"read_file","args":`+tc.args+`}}`)
			blocked := out != nil && out["decision"] == denyDecision
			if blocked != tc.block {
				t.Fatalf("blocked = %v, want %v: %v", blocked, tc.block, out)
			}
			if !tc.block {
				return
			}
			reason, _ := out["reason"].(string)
			// It names the file and the way round it, so the model has somewhere to
			// go rather than only a wall.
			if !strings.Contains(reason, "faramir run") {
				t.Errorf("the refusal names no way through: %s", reason)
			}
			// And not the reader-verb alternation the question was put with, which
			// describes this check rather than the file.
			if strings.Contains(reason, "matched deny pattern") {
				t.Errorf("the refusal quotes the pattern the question was asked with: %s", reason)
			}
		})
	}
}

// A command still routes: the path check must not swallow the tool this host
// runs commands through.
func TestThePathCheckLeavesCommandsToTheRewrite(t *testing.T) {
	out := runGuard(t, "agy",
		`{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","Cwd":"/etc/faramir"}}}`)
	if out["decision"] != "allow" {
		t.Fatalf("a command was not rewritten: %v", out)
	}
}

// Every host whose own rule file does not refuse a path asks the guard to.
// Claude Code is the exception and the only one: it enforces the deny rules
// `faramir init` writes, so a second refusal here would be one more thing to
// keep in step with the file that already says it.
//
// The others each fail differently and arrive at the same place. The
// Antigravity IDE has no rule file an install can write; opencode and Kilo Code
// have one whose "deny" is a prompt an autonomous run approves; pi has none
// either. The CLI has real deny rules and is included anyway, sharing one
// dialect with the IDE.
func TestEveryHostWithoutAnEnforcedRuleFileRefusesPaths(t *testing.T) {
	for name, h := range hosts {
		want := name != "claude"
		if h.refusesPaths != want {
			t.Errorf("%s refusesPaths = %v, want %v", name, h.refusesPaths, want)
		}
	}
}

// The deny list is a matcher built to find a path inside other text, which is
// what a command line is. A tool's arguments are not: they carry prose beside
// paths, and a sentence naming the age key is not a call to open it.
//
// Refusing one is not a safe failure. It blocks ordinary work on a file that
// merely mentions a path, and the refusal names the whole sentence as though it
// were a filename. Worse, whether it happened depended on the text carrying a
// newline, so the same content refused or passed for a reason nobody could see.
func TestProseNamingAProtectedPathIsNotACallToOpenIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  string
		block bool
	}{
		{"a sentence mentioning the key",
			`{"Path":"/srv/docs/notes.md","Content":"The key lives at /etc/faramir/age.key and is never read."}`, false},
		// The same content with a newline in it. Before the argument had to look
		// like a path, this passed where the line above was refused.
		{"the same sentence across two lines",
			`{"Path":"/srv/docs/notes.md","Content":"line one\nsee /etc/faramir/age.key\n"}`, false},
		{"a relative path, which is left to the agent to have made absolute",
			`{"Path":"faramir/age.key"}`, false},
		{"the path itself", `{"Path":"/etc/faramir/age.key"}`, true},
		// Shaped like a path and refused, spaces and all: the argument is quoted
		// into the question, so a space does not end it.
		{"a protected path carrying a space",
			`{"Path":"/etc/faramir/my secrets/age.key"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := runGuard(t, "antigravity",
				`{"toolCall":{"name":"write_file","args":`+tc.args+`}}`)
			blocked := out != nil && out["decision"] == denyDecision
			if blocked != tc.block {
				t.Fatalf("blocked = %v, want %v: %v", blocked, tc.block, out)
			}
			if !tc.block {
				return
			}
			// And it names the file rather than the argument it was found in.
			reason, _ := out["reason"].(string)
			if strings.Contains(reason, "The key lives at") {
				t.Errorf("the refusal names a sentence as though it were a file: %s", reason)
			}
		})
	}
}

// A "~" is the operator's home written the way a person writes it, and the
// rules are rendered against the real path. One left as given matches none of
// them, so a tool handed the tilde form would be refused nothing that the same
// file is refused by its absolute name.
//
// Asserted as an equivalence rather than against a verdict: which paths a host
// refuses is what its operator declared, and a test naming one would pass or
// fail on the config rather than on this.
func TestTheTildeFormIsAnsweredLikeTheAbsoluteOne(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		t.Skip("no home to expand against")
	}
	for _, rest := range []string{
		"/.ssh/id_ed25519",
		"/.config/sops/age/keys.txt",
		"/.luks/luks.key",
		"/src/app/main.go",
	} {
		t.Run(rest, func(t *testing.T) {
			tilde := runGuard(t, "antigravity",
				`{"toolCall":{"name":"read_file","args":{"Path":`+quoteJSON("~"+rest)+`}}}`)
			absolute := runGuard(t, "antigravity",
				`{"toolCall":{"name":"read_file","args":{"Path":`+quoteJSON(home+rest)+`}}}`)
			if (tilde == nil) != (absolute == nil) {
				t.Errorf("~%s and %s are answered differently: %v vs %v",
					rest, home+rest, tilde, absolute)
			}
		})
	}
}

// quoteJSON renders one string as a JSON value, for building a payload by hand.
func quoteJSON(s string) string {
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(out)
}
