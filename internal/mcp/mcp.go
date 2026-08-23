// Package mcp is an MCP (stdio) server exposing the broker to a coding agent,
// run as `faramir mcp`. The tool descriptions carry the weight: a distinct
// tool is more discoverable to a model than prose in a config file.
//
// Two tools, for the two things an agent has to be told: faramir_run, because a
// credential must not go any other way, and faramir_refs, because faramir_run's
// arguments are refs. `faramir status` answers an operator's questions and
// stays a subcommand, an advertised tool costing a slot in every session's
// context.
//
// This list is the one list: pi ships no MCP and registers the same tools from
// the extension faramir installs, rendered from Tools() below rather than
// carrying a copy.
//
// Protocol: JSON-RPC 2.0 over stdio, MCP 2025-06-18.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

const (
	serverName      = "faramir"
	protocolVersion = "2025-06-18"
	defaultSocket   = "/run/faramir/broker.sock"
	// The schema's own type names and the only JSON-RPC version there is. These
	// are the wire format's vocabulary, not this package's.
	typeObject     = "object"
	typeString     = "string"
	jsonrpcVersion = "2.0"
)

func socketPath() string {
	if v := os.Getenv("FARAMIR_SOCKET"); v != "" {
		return v
	}
	return defaultSocket
}

// Tool is one advertised tool. Exported, with Tools below, because pi's
// extension is rendered from this list rather than carrying a copy.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// Tools is what this server advertises, in the order it advertises them. The
// slice is a copy and each InputSchema is not: the schemas are the maps this
// server hands to tools/list, so a caller that writes into one changes what
// every session is told a tool takes.
func Tools() []Tool { return slices.Clone(tools) }

var tools = []Tool{
	{
		Name: "faramir_run",
		Description: "Run a command that needs credentials. The only way to: they are " +
			"not in your environment, and reading the managed secrets is blocked.\n\n" +
			"Values are injected as environment variables named by faramir:// refs, " +
			"never substituted into the command line. Output comes back with each " +
			"replaced by a «SECRET:ref» token; transforming it to get around that is a " +
			"policy violation. Call faramir_refs for the names.\n\n" +
			"Example: cmd=[\"printenv\",\"ROUTER_PW\"], " +
			"env_refs={\"ROUTER_PW\":\"faramir://home/router/admin\"}. No shell is " +
			"spawned: for a pipeline pass cmd=[\"bash\",\"-lc\",\"…\"].",
		InputSchema: map[string]any{
			"type": typeObject,
			"properties": map[string]any{
				"cmd": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": typeString},
					"minItems":    1,
					"description": "argv array. Not a shell string; no shell is spawned for you.",
				},
				"env_refs": map[string]any{
					"type":                 typeObject,
					"additionalProperties": map[string]any{"type": typeString},
					"description":          "Map of ENV_VAR name -> faramir:// URI to inject.",
				},
				"cwd": map[string]any{
					"type":        typeString,
					"description": "Absolute working directory. Defaults to the working tree.",
				},
				"timeout_sec": map[string]any{
					"type": "integer",
					"description": "Seconds before the command is killed. Clamped to the " +
						"broker's maximum.",
				},
			},
			"required": []string{"cmd"},
		},
	},
	{
		Name: "faramir_refs",
		Description: "List the faramir:// refs the broker can inject. Names only, " +
			"never values. These are what faramir_run's env_refs takes.",
		InputSchema: map[string]any{"type": typeObject, "properties": map[string]any{}},
	},
}

type brokerResponse struct {
	ExitCode   *int   `json:"exit_code"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
	TimedOut   bool   `json:"timed_out"`
	LogID      string `json:"log_id"`
	Redactions []struct {
		Token string `json:"token"`
		Count int    `json:"count"`
	} `json:"redactions"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func textResult(content string, isError bool) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": content}},
		"isError": isError,
	}
}

// call performs one request/response round trip against the broker socket.
func call(request map[string]any) (*brokerResponse, error) {
	request["version"] = version.Version
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", socketPath(), err)
	}
	defer func() { _ = conn.Close() }()

	if err := sockutil.Send(conn, request); err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<26)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, errors.New("broker closed the connection without responding")
	}
	var response brokerResponse
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, fmt.Errorf("malformed response: %w", err)
	}
	return &response, nil
}

func format(r *brokerResponse) map[string]any {
	if r.Error != nil {
		detail := r.Error.Code + ": " + r.Error.Message
		if r.LogID != "" {
			detail += "\n(operator can inspect log_id " + r.LogID + ")"
		}
		return textResult(detail, true)
	}

	var b strings.Builder
	b.WriteString(r.Output)

	var meta []string
	if r.ExitCode != nil {
		meta = append(meta, fmt.Sprintf("exit_code=%d", *r.ExitCode))
	}
	if len(r.Redactions) > 0 {
		var parts []string
		for _, red := range r.Redactions {
			parts = append(parts, fmt.Sprintf("%s ×%d", red.Token, red.Count))
		}
		meta = append(meta, "redacted: "+strings.Join(parts, ", "))
	}
	if r.Truncated {
		meta = append(meta, "output truncated")
	}
	if r.TimedOut {
		meta = append(meta, "timed out")
	}
	if r.LogID != "" {
		meta = append(meta, "log_id="+r.LogID)
	}
	if len(meta) > 0 {
		b.WriteString("\n[" + strings.Join(meta, "; ") + "]")
	}

	isError := r.ExitCode != nil && *r.ExitCode != 0
	return textResult(b.String(), isError)
}

// declaredArguments is the properties one tool's schema names, sorted. Read off
// the schema rather than listed a second time: a list beside it is one that
// drifts, and an argument the schema advertises and this refuses is a tool that
// cannot be called the way it says it can.
func declaredArguments(tool string) []string {
	var out []string
	for _, t := range tools {
		if t.Name != tool {
			continue
		}
		schema, _ := t.InputSchema.(map[string]any)
		props, _ := schema["properties"].(map[string]any)
		for key := range props {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// refuseUnknownArguments is a result for a call carrying an argument the tool
// does not declare, or nil where every one is declared.
//
// Refused rather than ignored, because the one that matters is silent. A model
// writing env= for env_refs= gets the command run with the variable unset and
// nothing said: `printenv` happens to exit non-zero, but a curl carrying an
// empty Authorization header reports success having authenticated as nobody.
// Injecting a ref is what this tool is for, so dropping the argument that names
// one is not a thing to pass over.
//
// A key beginning with "_" is left alone: that is where a client puts its own
// metadata, and it is not the model's spelling of anything.
func refuseUnknownArguments(tool string, known []string, arguments map[string]any) map[string]any {
	var unknown []string
	for key := range arguments {
		if strings.HasPrefix(key, "_") || slices.Contains(known, key) {
			continue
		}
		unknown = append(unknown, key)
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown)
	named := make([]string, 0, len(unknown))
	for _, key := range unknown {
		if near := nearest(known, key); near != "" {
			named = append(named, fmt.Sprintf("%q (did you mean %s?)", key, near))
			continue
		}
		named = append(named, fmt.Sprintf("%q", key))
	}
	takes := " It takes no arguments."
	if len(known) > 0 {
		takes = fmt.Sprintf(" It takes %s.", strings.Join(known, ", "))
	}
	return textResult(fmt.Sprintf("%s does not take %s.%s",
		tool, strings.Join(named, ", "), takes), true)
}

// nearest is the declared argument a misspelling most likely meant: one that
// begins with what was written, or that is contained in it. Enough for the case
// this exists for (env for env_refs) and silent about anything less obvious, a
// wrong guess reading as an instruction.
func nearest(known []string, written string) string {
	for _, name := range known {
		if strings.HasPrefix(name, written) || strings.Contains(written, name) {
			return name
		}
	}
	return ""
}

func callTool(name string, arguments map[string]any) map[string]any {
	var request map[string]any
	switch name {
	case "faramir_run":
		if refused := refuseUnknownArguments(name, declaredArguments(name), arguments); refused != nil {
			return refused
		}
		// The two likeliest ways to call this wrong, told apart: a caller that
		// passed nothing needs "cmd is required", and one that passed a shell
		// string needs to be told there is no shell. One message for both blamed
		// a string on a call that carried none.
		raw, present := arguments["cmd"]
		if !present || raw == nil {
			return textResult("cmd is required: an array naming the program and its "+
				`arguments, like cmd=["printenv","TOKEN"].`, true)
		}
		cmd, ok := raw.([]any)
		if !ok {
			return textResult("cmd must be an array of strings, not a shell string. "+
				`Use cmd=["ansible-playbook","site.yml"], or `+
				`cmd=["bash","-lc","a | b"] when you need a pipeline.`, true)
		}
		if len(cmd) == 0 {
			return textResult("cmd must name a program: it is an empty array.", true)
		}
		for i, arg := range cmd {
			if _, isString := arg.(string); !isString {
				return textResult(fmt.Sprintf(
					"cmd[%d] is %T, but every element must be a string.", i, arg), true)
			}
		}
		request = map[string]any{"op": "run", "cmd": cmd}
		for _, key := range []string{"env_refs", "cwd", "timeout_sec"} {
			if v, ok := arguments[key]; ok && v != nil {
				request[key] = v
			}
		}
		// This process runs where the agent's session does, so its own directory is
		// the one meant. An explicit cwd wins.
		if _, named := request["cwd"]; !named {
			if here, err := os.Getwd(); err == nil {
				request["cwd"] = here
			}
		}
	case "faramir_refs":
		if refused := refuseUnknownArguments(name, declaredArguments(name), arguments); refused != nil {
			return refused
		}
		request = map[string]any{"op": "refs"}
	default:
		return textResult("unknown tool: "+name, true)
	}

	response, err := call(request)
	if err != nil {
		return textResult("secrets broker unavailable: "+err.Error(), true)
	}
	return format(response)
}

type message struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Name            string         `json:"name"`
		Arguments       map[string]any `json:"arguments"`
	} `json:"params"`
}

func handle(m *message) map[string]any {
	var result any

	switch {
	case m.Method == "initialize":
		// Echoed only when this server speaks it; otherwise the client holds the
		// server to a version it never supported.
		negotiated := protocolVersion
		if m.Params.ProtocolVersion == protocolVersion {
			negotiated = m.Params.ProtocolVersion
		}
		result = map[string]any{
			"protocolVersion": negotiated,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": serverName, "version": version.Version},
			"instructions": "Any command needing a credential goes through faramir_run. " +
				"Secrets are named (faramir://…); you never see a value.",
		}
	case m.Method == "tools/list":
		result = map[string]any{"tools": tools}
	case m.Method == "tools/call":
		args := m.Params.Arguments
		if args == nil {
			args = map[string]any{}
		}
		result = callTool(m.Params.Name, args)
	case m.Method == "ping":
		result = map[string]any{}
	case strings.HasPrefix(m.Method, "notifications/"):
		return nil
	default:
		// A notification (no id) gets no reply, not even an error.
		if len(m.ID) == 0 || string(m.ID) == "null" {
			return nil
		}
		return map[string]any{
			"jsonrpc": jsonrpcVersion, "id": m.ID,
			"error": map[string]any{
				"code": -32601, "message": "method not found: " + m.Method,
			},
		}
	}

	if len(m.ID) == 0 || string(m.ID) == "null" {
		return nil
	}
	return map[string]any{"jsonrpc": jsonrpcVersion, "id": m.ID, "result": result}
}

// Run is the `faramir mcp` subcommand.
func Run(args []string) int {
	// A stdio server started by the agent with a fixed argv. A flag set, rather
	// than scanning argv, so --version behaves as it does for the daemons; it is
	// how an operator confirms which build the agent talks to.
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}
	return serve(os.Stdin, os.Stdout)
}

func serve(stdin io.Reader, stdout io.Writer) int {
	in := bufio.NewScanner(stdin)
	// A tools/call response can carry a whole command's output.
	in.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	out := bufio.NewWriter(stdout)
	defer func() { _ = out.Flush() }()

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var m message
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			emit(out, map[string]any{
				"jsonrpc": jsonrpcVersion, "id": nil,
				"error": map[string]any{"code": -32700, "message": "parse error"},
			})
			continue
		}
		if response := handle(&m); response != nil {
			emit(out, response)
		}
	}
	// A failed read is not end of input: 0 would look like a clean exit with
	// the last request unanswered.
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "faramir mcp: "+err.Error())
		return 1
	}
	return 0
}

func emit(out *bufio.Writer, response map[string]any) {
	data, err := json.Marshal(response)
	if err != nil {
		return
	}
	_, _ = out.Write(data)
	_ = out.WriteByte('\n')
	_ = out.Flush()
}
