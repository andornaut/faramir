package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The plugins opencode and Kilo Code load, run.
//
// They are the one piece of shipped logic that is not Go, and the only thing
// standing between the model's command and a shell on those agents.  A syntax
// error or a mis-read decision there is not a broken feature: the plugin fails
// closed, so it is every command in the project refusing to run.
//
// Driven through node, which parses and executes the same module a Bun-based
// agent would.  Skipped where node is absent, like the rest of the suite the
// tests here do not require anything installed to be useful.

// driver imports one plugin, calls its tool.execute.before with the payload
// given, and prints what happened.  The two plugins differ in what a module
// exports, so which export to call is an argument.
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
	// payloadFile is what the stand-in wrote its stdin to, so a test can check
	// that the guard is asked about what the model actually sent.
	payloadFile string
	// replyFile is what the stand-in prints.  Empty means it prints nothing,
	// which is how the guard leaves a call alone.
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
		dir:         dir,
		modulePath:  filepath.Join(dir, "plugin.mjs"),
		exportKind:  exportKind,
		cli:         filepath.Join(dir, "guard-stand-in"),
		payloadFile: filepath.Join(dir, "payload.json"),
		replyFile:   filepath.Join(dir, "reply.json"),
		statusFile:  filepath.Join(dir, "status"),
	}
	// .mjs, because a .js is CommonJS to node unless a package.json says
	// otherwise, and these are modules.  The bytes are the shipped ones.
	body, err := readAsset("agent/" + agent + "/plugin.js")
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
		"FARAMIR_CLI="+r.cli,
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

// Both plugins, because they are separate files: one fixed and the other left
// behind is the failure this catches.
func eachPlugin(t *testing.T, run func(t *testing.T, rig *pluginRig)) {
	t.Helper()
	for agent, exportKind := range map[string]string{
		"opencode": "named",
		"kilocode": "default",
	} {
		t.Run(agent, func(t *testing.T) { run(t, newPluginRig(t, agent, exportKind)) })
	}
}

// A rewrite is applied to the arguments the host handed in, all of them, which
// is how these agents change a call: there is no document to return.
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
		// The guard decides against what the model sent, so that is what it has
		// to be given.
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

// A refusal reaches the model as the error the tool call failed with, which is
// the only thing it can act on.
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

// Nothing written is a call the guard left alone: a backgrounded command, or
// one already under the redactor.  It runs unchanged rather than being refused.
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

// Every way of not getting a decision fails closed.  A guard that cannot run is
// an install that is broken or absent, and running the command anyway would
// print whatever it found into the transcript.
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

// Every other tool is left alone without asking.  A plugin sees them all, and
// only a command has output worth redacting.
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
