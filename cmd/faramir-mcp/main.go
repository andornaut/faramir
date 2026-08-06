// Command faramir-mcp is an MCP (stdio) server exposing the broker to a coding
// agent.
//
// A distinct tool is far more discoverable to a model than a convention
// documented in prose, so the interesting work here is the tool descriptions:
// they have to make it obvious that faramir_run is the *only* way to run a
// command that needs credentials, and that secrets are named, never pasted.
//
// Protocol: JSON-RPC 2.0 over stdio, MCP 2025-06-18.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

const (
	serverName      = "faramir"
	protocolVersion = "2025-06-18"
	defaultSocket   = "/run/faramir/broker.sock"
)

func socketPath() string {
	if v := os.Getenv("FARAMIR_SOCKET"); v != "" {
		return v
	}
	return defaultSocket
}

// --------------------------------------------------------------------------
// Tool definitions
// --------------------------------------------------------------------------

type tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

var tools = []tool{
	{
		Name: "faramir_run",
		Description: "Run a command that needs credentials. This is the ONLY way to run such " +
			"a command: the credentials do not exist in your environment, and reading " +
			"or decrypting the secret store directly is blocked.\n\n" +
			"The command runs as a separate uid that holds the keys. Output comes back " +
			"with every known secret value replaced by a stable «SECRET:ref» token, so " +
			"you can confirm a credential reached the right place without ever seeing " +
			"it. Do not attempt to work around this: transformed output (base64, rev, " +
			"cut) is a policy violation, not a puzzle.\n\n" +
			"Secrets are referenced by name using secret:// URIs and are injected as " +
			"environment variables only; they are never substituted into the command " +
			"line. Call faramir_list_secrets to discover available names.\n\n" +
			"Example: cmd=[\"printenv\",\"ROUTER_PW\"], " +
			"env_refs={\"ROUTER_PW\":\"secret://home/router/admin\"}.\n" +
			"For a pipeline, pass cmd=[\"bash\",\"-lc\",\"…\"] explicitly; no shell is " +
			"spawned for you. A bare command name is looked up on the broker's " +
			"configured PATH; pass an absolute path for anything else.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"cmd": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"minItems":    1,
					"description": "argv array. Not a shell string; no shell is spawned for you.",
				},
				"env_refs": map[string]any{
					"type":                 "object",
					"additionalProperties": map[string]any{"type": "string"},
					"description":          "Map of ENV_VAR name -> secret:// URI to inject.",
				},
				"cwd": map[string]any{
					"type": "string",
					"description": "Absolute working directory. Defaults to the working tree; " +
						"your edits are picked up as soon as they are saved.",
				},
				"timeout_sec": map[string]any{
					"type":        "integer",
					"description": "Seconds before the command is killed. Default 600.",
				},
			},
			"required": []string{"cmd"},
		},
	},
	{
		Name: "faramir_list_secrets",
		Description: "List the secret:// references the broker can inject. Returns names only, " +
			"never values. Use this to find the right ref for faramir_run's env_refs.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		Name: "faramir_status",
		Description: "Show broker configuration: which secret files are loaded, how many refs " +
			"exist, and the default working directory commands run in.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
}

// --------------------------------------------------------------------------
// Broker calls
// --------------------------------------------------------------------------

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
	conn, err := net.Dial("unix", socketPath())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", socketPath(), err)
	}
	defer conn.Close()

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
		return nil, fmt.Errorf("broker closed the connection without responding")
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

func callTool(name string, arguments map[string]any) map[string]any {
	var request map[string]any
	switch name {
	case "faramir_run":
		cmd, _ := arguments["cmd"].([]any)
		request = map[string]any{"op": "exec", "cmd": cmd}
		for _, key := range []string{"env_refs", "cwd", "timeout_sec"} {
			if v, ok := arguments[key]; ok && v != nil {
				request[key] = v
			}
		}
	case "faramir_list_secrets":
		request = map[string]any{"op": "list_secrets"}
	case "faramir_status":
		request = map[string]any{"op": "status"}
	default:
		return textResult("unknown tool: "+name, true)
	}

	response, err := call(request)
	if err != nil {
		return textResult("secret broker unavailable: "+err.Error(), true)
	}
	return format(response)
}

// --------------------------------------------------------------------------
// JSON-RPC
// --------------------------------------------------------------------------

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
		negotiated := m.Params.ProtocolVersion
		if negotiated == "" {
			negotiated = protocolVersion
		}
		result = map[string]any{
			"protocolVersion": negotiated,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": serverName, "version": version.Version},
			"instructions": "Any command that needs a credential must go through faramir_run. " +
				"Secrets are referenced by name (secret://…); their values are never " +
				"visible to you and never need to be.",
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
		// A notification (no id) gets no reply, even an error one.
		if len(m.ID) == 0 || string(m.ID) == "null" {
			return nil
		}
		return map[string]any{
			"jsonrpc": "2.0", "id": json.RawMessage(m.ID),
			"error": map[string]any{
				"code": -32601, "message": "method not found: " + m.Method,
			},
		}
	}

	if len(m.ID) == 0 || string(m.ID) == "null" {
		return nil
	}
	return map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(m.ID), "result": result}
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	// No flags: this is a stdio server, started by the agent, never by hand.
	// --version is the one exception, because it is how an operator confirms
	// which build the agent is actually talking to.
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Println("faramir-mcp " + version.Version)
			return 0
		}
	}

	in := bufio.NewScanner(os.Stdin)
	// A tools/call response can carry a whole command's output.
	in.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var m message
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			emit(out, map[string]any{
				"jsonrpc": "2.0", "id": nil,
				"error": map[string]any{"code": -32700, "message": "parse error"},
			})
			continue
		}
		if response := handle(&m); response != nil {
			emit(out, response)
		}
	}
	return 0
}

func emit(out *bufio.Writer, response map[string]any) {
	data, err := json.Marshal(response)
	if err != nil {
		return
	}
	out.Write(data)
	out.WriteByte('\n')
	out.Flush()
}
