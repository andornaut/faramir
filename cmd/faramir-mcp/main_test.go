package main

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

// fakeBroker answers one canned response per connection and records the
// requests it was sent, which is how the request-shaping tests assert on what
// the MCP layer put on the wire rather than on what came back.
type fakeBroker struct {
	requests chan map[string]any
	reply    map[string]any
}

func newFakeBroker(t *testing.T, reply map[string]any) *fakeBroker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("FARAMIR_SOCKET", path)

	b := &fakeBroker{requests: make(chan map[string]any, 8), reply: reply}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := sockutil.ReadLine(conn, 1<<20)
			var req map[string]any
			_ = json.Unmarshal(line, &req)
			b.requests <- req
			_ = sockutil.Send(conn, b.reply)
			_ = conn.Close()
		}
	}()
	return b
}

func (b *fakeBroker) lastRequest(t *testing.T) map[string]any {
	t.Helper()
	select {
	case req := <-b.requests:
		return req
	default:
		t.Fatal("the broker was never called")
		return nil
	}
}

func resultText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("no content in %v", result)
	}
	entry, _ := content[0].(map[string]any)
	text, _ := entry["text"].(string)
	return text
}

// -- request shaping --------------------------------------------------------

func TestAnArgvArrayReachesTheBrokerIntact(t *testing.T) {
	b := newFakeBroker(t, map[string]any{"exit_code": 0, "output": "hi\n"})
	callTool("faramir_run", map[string]any{
		"cmd":      []any{"echo", "hi"},
		"env_refs": map[string]any{"PW": "secret://a/b"},
	})

	req := b.lastRequest(t)
	cmd, _ := req["cmd"].([]any)
	if len(cmd) != 2 || cmd[0] != "echo" || cmd[1] != "hi" {
		t.Errorf("argv did not survive: %v", req["cmd"])
	}
	if req["env_refs"] == nil {
		t.Error("env_refs was dropped")
	}
}

// A model that writes cmd as a shell string is the likeliest way to call this
// tool wrong.  The type assertion yields nil, so without a check the broker is
// sent a null argv and answers about a malformed request, saying nothing about
// the shell string that caused it.
func TestAShellStringCmdIsRejectedWithAUsableMessage(t *testing.T) {
	newFakeBroker(t, map[string]any{"exit_code": 0, "output": ""})
	result := callTool("faramir_run", map[string]any{"cmd": "echo hi"})

	if isError, _ := result["isError"].(bool); !isError {
		t.Fatal("a shell string for cmd was accepted")
	}
	text := resultText(t, result)
	if !strings.Contains(text, "array") {
		t.Errorf("the message does not say what was wrong: %q", text)
	}
}

func TestAnEmptyCmdIsRejected(t *testing.T) {
	newFakeBroker(t, map[string]any{"exit_code": 0, "output": ""})
	result := callTool("faramir_run", map[string]any{"cmd": []any{}})

	if isError, _ := result["isError"].(bool); !isError {
		t.Error("an empty argv was accepted")
	}
}

func TestAnUnknownToolIsAnError(t *testing.T) {
	result := callTool("faramir_delete_everything", map[string]any{})
	if isError, _ := result["isError"].(bool); !isError {
		t.Error("an unknown tool name was not an error")
	}
}

func TestTheBrokerBeingDownIsReportedNotPanicked(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	result := callTool("faramir_list_secrets", map[string]any{})

	if isError, _ := result["isError"].(bool); !isError {
		t.Error("an unreachable broker was reported as success")
	}
	if text := resultText(t, result); !strings.Contains(text, "unavailable") {
		t.Errorf("unhelpful message: %q", text)
	}
}

// The MCP server builds broker requests by hand, so nothing but this ties its
// field names to the parser that reads them.  A rename on either side would
// otherwise leave every agent tool call failing while the whole suite passed.
func TestEveryToolProducesARequestTheBrokerAccepts(t *testing.T) {
	for _, tc := range []struct {
		tool string
		args map[string]any
		want protocol.Request
	}{
		{
			tool: "faramir_run",
			args: map[string]any{
				"cmd":         []any{"ansible-playbook", "site.yml"},
				"env_refs":    map[string]any{"PW": "secret://a/b"},
				"cwd":         "/home/agent/work",
				"timeout_sec": float64(30),
			},
			want: protocol.Request{
				Op: "exec", Cmd: []string{"ansible-playbook", "site.yml"},
				Cwd: "/home/agent/work", HasCwd: true,
				EnvRefs: map[string]string{"PW": "secret://a/b"}, TimeoutSec: 30,
			},
		},
		{
			tool: "faramir_list_secrets",
			args: map[string]any{},
			want: protocol.Request{Op: "list_secrets", EnvRefs: map[string]string{}},
		},
		{
			tool: "faramir_status",
			args: map[string]any{},
			want: protocol.Request{Op: "status", EnvRefs: map[string]string{}},
		},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			b := newFakeBroker(t, map[string]any{"exit_code": 0, "output": ""})
			callTool(tc.tool, tc.args)

			// Round tripped through JSON, as the broker really receives it.
			raw, err := json.Marshal(b.lastRequest(t))
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			got, err := protocol.Parse(payload)
			if err != nil {
				t.Fatalf("the broker rejected what the MCP server sent: %v", err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("got %+v, want %+v", *got, tc.want)
			}
		})
	}
}

// -- response formatting ----------------------------------------------------

func TestANonZeroExitIsMarkedAsAnError(t *testing.T) {
	newFakeBroker(t, map[string]any{"exit_code": 2, "output": "nope\n"})
	result := callTool("faramir_run", map[string]any{"cmd": []any{"false"}})

	if isError, _ := result["isError"].(bool); !isError {
		t.Error("a failing command was reported as success")
	}
	if text := resultText(t, result); !strings.Contains(text, "exit_code=2") {
		t.Errorf("the exit code is not visible: %q", text)
	}
}

func TestRedactionsAndLogIDAreReportedToTheAgent(t *testing.T) {
	newFakeBroker(t, map[string]any{
		"exit_code": 0,
		"output":    "pw=«SECRET:a/b»\n",
		"log_id":    "2026-01-01T00:00:00Z-abcd",
		"redactions": []any{
			map[string]any{"token": "«SECRET:a/b»", "count": 1},
		},
	})
	result := callTool("faramir_run", map[string]any{"cmd": []any{"printenv"}})

	text := resultText(t, result)
	for _, want := range []string{"«SECRET:a/b»", "log_id=", "redacted:"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %q", want, text)
		}
	}
}

func TestABrokerErrorBecomesAToolError(t *testing.T) {
	newFakeBroker(t, map[string]any{
		"error":  map[string]any{"code": "unknown_secret", "message": "unknown secret ref: nope"},
		"log_id": "2026-01-01T00:00:00Z-abcd",
	})
	result := callTool("faramir_run", map[string]any{"cmd": []any{"true"}})

	if isError, _ := result["isError"].(bool); !isError {
		t.Fatal("a broker error was reported as success")
	}
	if text := resultText(t, result); !strings.Contains(text, "unknown_secret") {
		t.Errorf("the broker's code is not visible: %q", text)
	}
}

// -- JSON-RPC ---------------------------------------------------------------

func decodeReply(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m message
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return handle(&m)
}

// The client's requested version must not be echoed back unless the server
// actually speaks it: echoing an arbitrary string claims support for anything.
func TestInitializeDoesNotClaimAnUnsupportedProtocolVersion(t *testing.T) {
	reply := decodeReply(t, `{"jsonrpc":"2.0","id":1,"method":"initialize",
		"params":{"protocolVersion":"1999-01-01"}}`)
	result, _ := reply["result"].(map[string]any)

	if got := result["protocolVersion"]; got != protocolVersion {
		t.Errorf("claimed to speak %v; this server speaks %v", got, protocolVersion)
	}
}

func TestInitializeEchoesAVersionItDoesSpeak(t *testing.T) {
	reply := decodeReply(t, `{"jsonrpc":"2.0","id":1,"method":"initialize",
		"params":{"protocolVersion":"`+protocolVersion+`"}}`)
	result, _ := reply["result"].(map[string]any)

	if got := result["protocolVersion"]; got != protocolVersion {
		t.Errorf("got %v, want %v", got, protocolVersion)
	}
}

// A notification has no id and must draw no reply at all: answering one is a
// protocol violation that some clients treat as a fatal error.
func TestANotificationDrawsNoReply(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"some/unknown/notification"}`,
	} {
		if reply := decodeReply(t, raw); reply != nil {
			t.Errorf("%s drew a reply: %v", raw, reply)
		}
	}
}

func TestAnUnknownMethodWithAnIDGetsMethodNotFound(t *testing.T) {
	reply := decodeReply(t, `{"jsonrpc":"2.0","id":7,"method":"resources/list"}`)
	errObj, _ := reply["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("no error in %v", reply)
	}
	if code, _ := errObj["code"].(int); code != -32601 {
		t.Errorf("got code %v, want -32601", errObj["code"])
	}
}

func TestToolsListAdvertisesEveryTool(t *testing.T) {
	reply := decodeReply(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	result, _ := reply["result"].(map[string]any)
	listed, _ := result["tools"].([]tool)

	names := map[string]bool{}
	for _, tl := range listed {
		names[tl.Name] = true
		if tl.Description == "" || tl.InputSchema == nil {
			t.Errorf("%s is missing a description or schema", tl.Name)
		}
	}
	for _, want := range []string{"faramir_run", "faramir_list_secrets", "faramir_status"} {
		if !names[want] {
			t.Errorf("%s is not advertised", want)
		}
	}
}

// -- the stdio loop ---------------------------------------------------------

// Framing is the whole contract with the client: exactly one JSON object per
// line on stdout, and nothing else on stdout ever, since anything else there
// is read as a protocol message.
func TestEachRequestProducesExactlyOneLineAndNotificationsProduceNone(t *testing.T) {
	newFakeBroker(t, map[string]any{"exit_code": 0, "output": "hi\n"})
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		``,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"faramir_run","arguments":{"cmd":["echo","hi"]}}}`,
	}, "\n") + "\n")

	var out strings.Builder
	if code := serve(in, &out); code != 0 {
		t.Errorf("clean input exited %d", code)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (the notification and the blank must draw none):\n%s",
			len(lines), out.String())
	}
	for i, line := range lines {
		var reply map[string]any
		if err := json.Unmarshal([]byte(line), &reply); err != nil {
			t.Errorf("line %d is not one JSON object: %v", i, err)
		}
		if reply["jsonrpc"] != "2.0" {
			t.Errorf("line %d is missing the jsonrpc version", i)
		}
	}
}

func TestUnparseableInputDrawsAParseErrorAndTheLoopContinues(t *testing.T) {
	in := strings.NewReader("{not json\n" +
		`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")

	var out strings.Builder
	serve(in, &out)

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %s", len(lines), out.String())
	}
	var first map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	errObj, _ := first["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != -32700 {
		t.Errorf("want a -32700 parse error, got %s", lines[0])
	}
}

// A read that fails mid-session must not look like a clean exit: the client
// would see the server succeed with its last request simply unanswered.
func TestAFailedReadIsNotASuccessfulExit(t *testing.T) {
	var out strings.Builder
	if code := serve(errAfterOneLine{}, &out); code == 0 {
		t.Error("a read error exited 0")
	}
}

type errAfterOneLine struct{ done bool }

func (r errAfterOneLine) Read(p []byte) (int, error) {
	return 0, errors.New("connection reset")
}

// The id has to come back exactly as sent: a client matches replies on it, and
// a string id re-emitted as a number is a reply it will never match.
func TestTheRequestIDIsEchoedWithItsOriginalType(t *testing.T) {
	reply := decodeReply(t, `{"jsonrpc":"2.0","id":"abc","method":"ping"}`)
	raw, err := json.Marshal(reply["id"])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `"abc"` {
		t.Errorf("id came back as %s, want \"abc\"", raw)
	}
}
