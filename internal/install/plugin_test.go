package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The plugins opencode and Kilo Code load, run.  The one piece of shipped logic
// that is not Go, and it fails closed: a syntax error there is every command in
// the project refusing to run.  Driven through node, skipped where it is
// absent.

// driver imports one plugin, calls its tool.execute.before, and prints what
// happened.  Which export to call is an argument, the two differing.
const driver = `
import { pathToFileURL } from "node:url"

const [, , modulePath, exportKind] = process.argv
const module = await import(pathToFileURL(modulePath).href)
const factory = exportKind === "default" ? module.default.server : module.faramir
const hooks = await factory({})
const input = JSON.parse(process.env.HOOK_INPUT)
const output = JSON.parse(process.env.HOOK_OUTPUT)
try {
  await hooks["tool.execute.before"](input, output)
  console.log(JSON.stringify({ ran: true, args: output.args }))
} catch (err) {
  console.log(JSON.stringify({ ran: false, error: String(err.message) }))
}
`

type hookResult struct {
	Ran   bool           `json:"ran"`
	Args  map[string]any `json:"args"`
	Error string         `json:"error"`
}

// pluginRig is one plugin set up to run: the module, a stand-in for the guard,
// and the file that stand-in answers with.
type pluginRig struct {
	dir        string
	modulePath string
	exportKind string
	cli        string
	// payloadFile is the stand-in's stdin, so a test can check what the guard
	// was asked about.
	payloadFile string
	// replyFile is what the stand-in prints; empty leaves the call alone.
	replyFile  string
	statusFile string
}

func newPluginRig(t *testing.T, agent, exportKind string) *pluginRig {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	dir := t.TempDir()
	rig := &pluginRig{
		dir:        dir,
		modulePath: filepath.Join(dir, "plugin.mjs"),
		exportKind: exportKind,
		// Named faramir, being what the rendered plugin execs.
		cli:         filepath.Join(dir, "faramir"),
		payloadFile: filepath.Join(dir, "payload.json"),
		replyFile:   filepath.Join(dir, "reply.json"),
		statusFile:  filepath.Join(dir, "status"),
	}
	// Rendered here the way an enrolment renders it, with BinDir pointing at
	// this test's own directory: the plugin execs the installed path rather than
	// reading one from the environment, so a stand-in guard has to be installed
	// where the rendered file will look for it.
	//
	// .mjs: a .js is CommonJS to node without a package.json.  The bytes are the
	// shipped ones otherwise.
	body, err := renderData("agent/plugin.js.tmpl", pluginData{
		BinDir:        dir,
		Agent:         agent,
		Path:          ".test/plugin.js",
		DefaultExport: exportKind == "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	write(t, rig.modulePath, string(body), 0o644)
	write(t, filepath.Join(dir, "driver.mjs"), driver, 0o644)
	write(t, rig.cli, "#!/bin/sh\ncat >"+rig.payloadFile+"\ncat "+rig.replyFile+
		"\nexit \"$(cat "+rig.statusFile+")\"\n", 0o755)
	write(t, rig.replyFile, "", 0o644)
	write(t, rig.statusFile, "0", 0o644)
	return rig
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// call runs the hook against one tool call and returns what the plugin did.
func (r *pluginRig) call(t *testing.T, tool string, args map[string]any) hookResult {
	t.Helper()
	input, err := json.Marshal(map[string]any{"tool": tool})
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(map[string]any{"args": args})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", filepath.Join(r.dir, "driver.mjs"), r.modulePath, r.exportKind)
	cmd.Env = append(os.Environ(),
		"HOOK_INPUT="+string(input),
		"HOOK_OUTPUT="+string(output))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("driver failed: %v\n%s", err, out)
	}
	var got hookResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver printed %q: %v", out, err)
	}
	return got
}

func (r *pluginRig) answers(t *testing.T, reply string) {
	t.Helper()
	write(t, r.replyFile, reply, 0o644)
}

// Both plugins, being separate files.
func eachPlugin(t *testing.T, run func(t *testing.T, rig *pluginRig)) {
	t.Helper()
	for agent, exportKind := range map[string]string{
		"opencode": "named",
		"kilocode": "default",
	} {
		t.Run(agent, func(t *testing.T) { run(t, newPluginRig(t, agent, exportKind)) })
	}
}

// Applied to the arguments the host handed in, there being no document to
// return.
func TestPluginAppliesARewrite(t *testing.T) {
	eachPlugin(t, func(t *testing.T, rig *pluginRig) {
		rig.answers(t, `{"decision":"rewrite","tool_input":`+
			`{"command":"source /usr/local/libexec/faramir/wrap.sh 'printenv'","description":"look"}}`)
		got := rig.call(t, "bash", map[string]any{"command": "printenv", "description": "look"})
		if !got.Ran {
			t.Fatalf("the command was refused: %s", got.Error)
		}
		if command, _ := got.Args["command"].(string); !strings.Contains(command, "wrap.sh") {
			t.Errorf("command = %q, want the wrapper", command)
		}
		if got.Args["description"] != "look" {
			t.Errorf("args = %v, want every field back", got.Args)
		}
		// The guard decides against what the model sent.
		payload, err := os.ReadFile(rig.payloadFile)
		if err != nil {
			t.Fatal(err)
		}
		var sent struct {
			ToolName  string         `json:"tool_name"`
			ToolInput map[string]any `json:"tool_input"`
		}
		if err := json.Unmarshal(payload, &sent); err != nil {
			t.Fatalf("the guard was sent %q: %v", payload, err)
		}
		if sent.ToolName != "bash" || sent.ToolInput["command"] != "printenv" {
			t.Errorf("the guard was sent %+v", sent)
		}
	})
}

// A refusal reaches the model as the error the tool call failed with.
func TestPluginThrowsADenial(t *testing.T) {
	eachPlugin(t, func(t *testing.T, rig *pluginRig) {
		rig.answers(t, `{"decision":"deny","reason":"Blocked: use faramir_run instead"}`)
		got := rig.call(t, "bash", map[string]any{"command": "printenv ROUTER_PW"})
		if got.Ran {
			t.Fatal("a denied command was allowed to run")
		}
		if !strings.Contains(got.Error, "faramir_run") {
			t.Errorf("error = %q, want the guard's reason", got.Error)
		}
	})
}

// Nothing written is a call the guard left alone, which runs unchanged.
func TestPluginLeavesAnUnansweredCallAlone(t *testing.T) {
	eachPlugin(t, func(t *testing.T, rig *pluginRig) {
		got := rig.call(t, "bash", map[string]any{"command": "tail -f log &"})
		if !got.Ran {
			t.Fatalf("the command was refused: %s", got.Error)
		}
		if got.Args["command"] != "tail -f log &" {
			t.Errorf("command = %v, want it untouched", got.Args["command"])
		}
	})
}

// Every way of not getting a decision fails closed: running the command anyway
// would print whatever it found into the transcript.
func TestPluginFailsClosed(t *testing.T) {
	eachPlugin(t, func(t *testing.T, rig *pluginRig) {
		t.Run("the guard exits non-zero", func(t *testing.T) {
			write(t, rig.statusFile, "2", 0o644)
			got := rig.call(t, "bash", map[string]any{"command": "ls"})
			if got.Ran {
				t.Error("the command ran after the guard refused to answer")
			}
		})
		t.Run("the answer is not JSON", func(t *testing.T) {
			write(t, rig.statusFile, "0", 0o644)
			rig.answers(t, "not a decision\n")
			if got := rig.call(t, "bash", map[string]any{"command": "ls"}); got.Ran {
				t.Error("the command ran on an answer that could not be read")
			}
		})
		t.Run("the answer is a decision it does not know", func(t *testing.T) {
			rig.answers(t, `{"decision":"allow"}`)
			if got := rig.call(t, "bash", map[string]any{"command": "ls"}); got.Ran {
				t.Error("the command ran on a decision the plugin does not understand")
			}
		})
		t.Run("faramir is not installed", func(t *testing.T) {
			rig.cli = filepath.Join(rig.dir, "not-installed")
			if got := rig.call(t, "bash", map[string]any{"command": "ls"}); got.Ran {
				t.Error("the command ran with no guard to ask")
			}
		})
	})
}

// A plugin sees every tool, and only a command has output worth redacting.
func TestPluginIgnoresEveryOtherTool(t *testing.T) {
	eachPlugin(t, func(t *testing.T, rig *pluginRig) {
		rig.answers(t, `{"decision":"deny","reason":"this should never be asked for"}`)
		got := rig.call(t, "read", map[string]any{"filePath": "/etc/hosts"})
		if !got.Ran {
			t.Fatalf("a read was refused: %s", got.Error)
		}
		if _, err := os.Stat(rig.payloadFile); err == nil {
			t.Error("the guard was asked about a tool that runs nothing")
		}
	})
}

// pi answers differently in both directions: a refusal is a value returned
// rather than an exception, and a rewrite mutates the event's own input.  Its
// extension is a file of its own, so it needs a driver of its own.
const piDriver = `
import { pathToFileURL } from "node:url"

const [, , modulePath] = process.argv
const module = await import(pathToFileURL(modulePath).href)
const handlers = {}
const tools = []
const pi = {
  on: (name, fn) => { handlers[name] = fn },
  registerTool: (t) => { tools.push(t) },
}
module.default(pi)
if (process.env.LIST_TOOLS) {
  console.log(JSON.stringify({ tools: tools.map((t) => t.name) }))
} else {
  const event = JSON.parse(process.env.HOOK_EVENT)
  const verdict = await handlers["tool_call"](event, {})
  console.log(JSON.stringify({ verdict: verdict ?? null, input: event.input }))
}
`

type piResult struct {
	Verdict *struct {
		Block  bool   `json:"block"`
		Reason string `json:"reason"`
	} `json:"verdict"`
	Input map[string]any `json:"input"`
}

type piCall func(t *testing.T, tool string, input map[string]any) piResult

// newPiRig is the pi extension rendered and loaded, with a stand-in guard where
// the rendered file will look for it.
func newPiRig(t *testing.T) (*pluginRig, piCall) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	dir := t.TempDir()
	rig := &pluginRig{
		dir:         dir,
		modulePath:  filepath.Join(dir, "extension.mjs"),
		cli:         filepath.Join(dir, "faramir"),
		payloadFile: filepath.Join(dir, "payload.json"),
		replyFile:   filepath.Join(dir, "reply.json"),
		statusFile:  filepath.Join(dir, "status"),
	}
	body, err := renderData("agent/pi/extension.ts.tmpl", pluginData{
		BinDir: dir, Agent: "pi", Path: ".pi/extensions/faramir.ts",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The shipped bytes, unaltered: the extension is a .ts that carries no type
	// annotations, so node runs it as it is.
	write(t, rig.modulePath, string(body), 0o644)
	write(t, filepath.Join(dir, "driver.mjs"), piDriver, 0o644)
	write(t, rig.cli, "#!/bin/sh\ncat >"+rig.payloadFile+"\ncat "+rig.replyFile+
		"\nexit \"$(cat "+rig.statusFile+")\"\n", 0o755)
	write(t, rig.replyFile, "", 0o644)
	write(t, rig.statusFile, "0", 0o644)

	call := func(t *testing.T, tool string, input map[string]any) piResult {
		t.Helper()
		event, err := json.Marshal(map[string]any{"toolName": tool, "input": input})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("node", filepath.Join(dir, "driver.mjs"), rig.modulePath)
		cmd.Env = append(os.Environ(), "HOOK_EVENT="+string(event))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("driver failed: %v\n%s", err, out)
		}
		var got piResult
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("driver printed %q: %v", out, err)
		}
		return got
	}
	return rig, call
}

func TestPiExtensionRewritesAndBlocks(t *testing.T) {
	rig, call := newPiRig(t)

	// A rewrite is a mutation of the event's own input, every field of it.
	rig.answers(t, `{"decision":"rewrite","tool_input":`+
		`{"command":"source /usr/local/libexec/faramir/wrap.sh 'printenv'","description":"look"}}`)
	got := call(t, "bash", map[string]any{"command": "printenv", "description": "look"})
	if got.Verdict != nil {
		t.Fatalf("a rewrite blocked the call: %+v", got.Verdict)
	}
	if command, _ := got.Input["command"].(string); !strings.Contains(command, "wrap.sh") {
		t.Errorf("command = %q, want the wrapper", command)
	}
	if got.Input["description"] != "look" {
		t.Errorf("input = %v, want every field back", got.Input)
	}

	// A refusal is returned, and carries the guard's reason to the model.
	rig.answers(t, `{"decision":"deny","reason":"Blocked: use faramir run instead"}`)
	got = call(t, "bash", map[string]any{"command": "printenv ROUTER_PW"})
	if got.Verdict == nil || !got.Verdict.Block {
		t.Fatalf("a denial did not block: %+v", got)
	}
	if !strings.Contains(got.Verdict.Reason, "Blocked") {
		t.Errorf("reason = %q, want the guard's own", got.Verdict.Reason)
	}
}

// Every way the guard can fail to answer ends in a blocked call: running the
// command without a decision would print whatever it found into the transcript.
func TestPiExtensionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  string
		status string
	}{
		{"the guard exits non-zero", "", "3"},
		{"the guard answers with something that is not JSON", "not json at all", "0"},
		{"the guard returns a decision it does not understand", `{"decision":"levitate"}`, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig, call := newPiRig(t)
			rig.answers(t, tc.reply)
			write(t, rig.statusFile, tc.status, 0o644)
			got := call(t, "bash", map[string]any{"command": "echo hello"})
			if got.Verdict == nil || !got.Verdict.Block {
				t.Fatalf("the call was not blocked: %+v", got)
			}
		})
	}
}

// Guarded by shape, so a tool nobody listed is covered when it carries a
// command; and a listed shell tool arriving without one is refused rather than
// waved through.
func TestPiExtensionGuardsByShape(t *testing.T) {
	rig, call := newPiRig(t)
	rig.answers(t, `{"decision":"deny","reason":"Blocked"}`)

	got := call(t, "some-new-shell", map[string]any{"command": "cat /etc/faramir/age.key"})
	if got.Verdict == nil || !got.Verdict.Block {
		t.Errorf("a tool this list never named ran a command unguarded: %+v", got)
	}
	got = call(t, "read", map[string]any{"filePath": "/etc/faramir/age.key"})
	if got.Verdict != nil {
		t.Errorf("a tool carrying no command was blocked: %+v", got.Verdict)
	}
	got = call(t, "bash", map[string]any{})
	if got.Verdict == nil || !got.Verdict.Block {
		t.Errorf("a known shell tool with no command string was not refused: %+v", got)
	}
}

// pi ships no MCP, so the tools the other hosts reach through it are the
// extension's to register.  Without faramir_run the guard's own refusal
// dead-ends: it tells the model to use a tool that would not exist.
func TestPiExtensionRegistersTheTools(t *testing.T) {
	rig, _ := newPiRig(t)
	cmd := exec.Command("node", filepath.Join(rig.dir, "driver.mjs"), rig.modulePath)
	cmd.Env = append(os.Environ(), "LIST_TOOLS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("driver failed: %v\n%s", err, out)
	}
	var got struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver printed %q: %v", out, err)
	}
	for _, want := range []string{"faramir_run", "faramir_list_secrets"} {
		if !slices.Contains(got.Tools, want) {
			t.Errorf("registered %v, want %s among them", got.Tools, want)
		}
	}
	// The same two internal/mcp advertises, and asserted the same way: this
	// extension is that tool list for the host with no MCP, so a tool on one side
	// and not the other is the drift worth failing on.
	if len(got.Tools) != 2 {
		t.Errorf("registered %d tools, want 2: %v", len(got.Tools), got.Tools)
	}
}
