package mcp

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
// requests, so the tests below assert on what went onto the wire.
type fakeBroker struct {
	requests chan map[string]any
	reply    map[string]any
}

func newFakeBroker(t *testing.T, reply map[string]any) *fakeBroker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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

// wantError asserts the call came back as an error carrying each of wants.  An
// MCP tool reports failure in the result, so "did it fail" is a field.
func wantError(t *testing.T, result map[string]any, wants ...string) {
	t.Helper()
	if isError, _ := result["isError"].(bool); !isError {
		t.Fatalf("not reported as an error: %v", result)
	}
	text := resultText(t, result)
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("message does not say %q: %q", want, text)
		}
	}
}

// -- request shaping --------------------------------------------------------

// What a tool call refuses, and what the agent is told: every row asserts on the
// text as well as the flag, the model having only the text to act on.
func TestRefusedToolCalls(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply map[string]any // the broker's canned answer; nil starts no broker
		tool  string
		args  map[string]any
		wants []string
	}{
		// The likeliest way to call this tool wrong: without the check the
		// broker gets a null argv and answers about a malformed request.
		{name: "a shell string for cmd",
			reply: map[string]any{"exit_code": 0, "output": ""},
			tool:  "faramir_run", args: map[string]any{"cmd": "echo hi"},
			wants: []string{"array"}},
		{name: "an empty argv",
			reply: map[string]any{"exit_code": 0, "output": ""},
			tool:  "faramir_run", args: map[string]any{"cmd": []any{}},
			wants: []string{"empty array"}},
		{name: "a tool that does not exist",
			tool: "faramir_delete_everything", args: map[string]any{},
			wants: []string{"unknown tool", "faramir_delete_everything"}},
		{name: "a command that failed",
			reply: map[string]any{"exit_code": 2, "output": "nope\n"},
			tool:  "faramir_run", args: map[string]any{"cmd": []any{"false"}},
			wants: []string{"exit_code=2"}},
		{name: "an error from the broker",
			reply: map[string]any{
				"error":  map[string]any{"code": "unknown_secret", "message": "unknown secret ref: nope"},
				"log_id": "2026-01-01T00:00:00Z-abcd"},
			tool: "faramir_run", args: map[string]any{"cmd": []any{"true"}},
			wants: []string{"unknown_secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.reply != nil {
				newFakeBroker(t, tc.reply)
			}
			wantError(t, callTool(tc.tool, tc.args), tc.wants...)
		})
	}
}

func TestTheBrokerBeingDownIsReportedNotPanicked(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	wantError(t, callTool("faramir_secret_refs", map[string]any{}), "unavailable")
}

// The MCP server builds broker requests by hand, so nothing else ties its field
// names to the parser that reads them.
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
				"env_refs":    map[string]any{"PW": "faramir://a/b"},
				"cwd":         "/home/agent/work",
				"timeout_sec": float64(30),
			},
			want: protocol.Request{
				Op: "exec", Cmd: []string{"ansible-playbook", "site.yml"},
				Cwd: "/home/agent/work", HasCwd: true,
				EnvRefs: map[string]string{"PW": "faramir://a/b"}, TimeoutSec: 30,
			},
		},
		{
			tool: "faramir_secret_refs",
			args: map[string]any{},
			want: protocol.Request{Op: "secret_refs", EnvRefs: map[string]string{}},
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

// -- JSON-RPC ---------------------------------------------------------------

func decodeReply(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m message
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return handle(&m)
}

// The version this server speaks, whatever was asked for: echoing the client's
// string would claim support for anything it named.
func TestInitializeAnswersWithTheVersionItSpeaks(t *testing.T) {
	for _, asked := range []string{"1999-01-01", protocolVersion} {
		reply := decodeReply(t, `{"jsonrpc":"2.0","id":1,"method":"initialize",
			"params":{"protocolVersion":"`+asked+`"}}`)
		result, _ := reply["result"].(map[string]any)
		if got := result["protocolVersion"]; got != protocolVersion {
			t.Errorf("asked for %s, answered %v; this server speaks %v",
				asked, got, protocolVersion)
		}
	}
}

// A notification has no id and draws no reply; answering one is a protocol
// violation some clients treat as fatal.
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
	listed, _ := result["tools"].([]Tool)

	names := map[string]bool{}
	for _, tl := range listed {
		names[tl.Name] = true
		if tl.Description == "" || tl.InputSchema == nil {
			t.Errorf("%s is missing a description or schema", tl.Name)
		}
	}
	for _, want := range []string{"faramir_run", "faramir_secret_refs"} {
		if !names[want] {
			t.Errorf("%s is not advertised", want)
		}
	}
	// Exactly those two, and the count is asserted so a tool added here has to
	// argue for itself: see the package doc.  Every tool spends a slot in every
	// session's context, so one an agent would call rarely and act on never costs
	// more than it answers.
	if len(listed) != 2 {
		t.Errorf("%d tools advertised, want 2: %v", len(listed), listed)
	}
}

// -- the stdio loop ---------------------------------------------------------

// Exactly one JSON object per line on stdout, and nothing else there ever:
// anything else is read as a protocol message.
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
	code, _ := errObj["code"].(float64)
	if errObj == nil || code != -32700 {
		t.Errorf("want a -32700 parse error, got %s", lines[0])
	}
}

// A read that fails mid-session must not look like a clean exit.
func TestAFailedReadIsNotASuccessfulExit(t *testing.T) {
	var out strings.Builder
	if code := serve(errAfterOneLine{}, &out); code == 0 {
		t.Error("a read error exited 0")
	}
}

type errAfterOneLine struct{}

func (r errAfterOneLine) Read(p []byte) (int, error) {
	return 0, errors.New("connection reset")
}

// The id comes back exactly as sent: a client matches replies on it.
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
