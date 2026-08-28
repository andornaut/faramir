package guard

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"
)

// The guard reads untrusted JSON on stdin, one payload from whichever of the
// six agents registered it. Whatever arrives, three things have to hold for
// every dialect, and each fails silently rather than loudly: a panic takes the
// hook down and a hook that is down guards nothing; an unmarshalable reply is
// one the agent cannot read and treats as no answer, which is a call let
// through; and a command the deny list does not name has to come back wrapped
// rather than as the model wrote it, or its output reaches the transcript
// unredacted.
//
// Asserted against the decision pipeline rather than Run, because Run reads a
// real stdin and writes a real stdout; the steps it takes are these.
func FuzzTheGuardDecidesAcrossEveryDialect(f *testing.F) {
	for _, s := range []string{
		`{"tool_name":"Bash","tool_input":{"command":"cat /etc/faramir/age.key"}}`,
		`{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`,
		`{"toolCall":{"name":"run_command","args":{"CommandLine":"ls","Cwd":"/srv"}}}`,
		`{"toolCall":{"name":"read_file","args":{"Path":"/etc/faramir/age.key"}}}`,
		`{"tool_name":"read","tool_input":{"filePath":"/etc/faramir/age.key"}}`,
		`{"tool_name":"bash","tool_input":{"command":"source /x/wrap.sh 'ls'"}}`,
		`{}`, `[]`, `null`, `"x"`, `42`,
		`{"tool_input":{"command":""}}`,
		`{"toolCall":{"name":"","args":{}}}`,
	} {
		f.Add(s)
	}
	hosts := []string{"claude", "opencode", "kilocode", "pi", "agy", "antigravity"}
	f.Fuzz(func(t *testing.T, payload string) {
		for _, name := range hosts {
			h, err := lookupHost(name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			decode := h.decode
			if decode == nil {
				decode = decodeToolInput
			}
			p, err := decode([]byte(payload))
			if err != nil {
				// A payload this dialect cannot read is refused at the door, which
				// is a decision in itself and a valid one.
				continue
			}
			// Every reply the guard can emit has to marshal, whichever branch
			// produced it: a refusal, a rewrite, and the refusal a bad path draws.
			mustMarshal(t, name, "deny", h.deny("why"))

			command := commandOf(p)
			if command == "" {
				continue
			}
			if _, denied := decide(command); denied {
				continue
			}
			wrapped, ok := wrap(h, command, p)
			if !ok {
				continue
			}
			// A command the deny list did not name and the wrapper did not decline
			// comes back wrapped. The one exception is a command already wrapped,
			// which is left as it is on purpose.
			if wrapped == command && !isWrapped(command) {
				t.Fatalf("%s: an unnamed command was emitted unwrapped: %q", name, command)
			}
			updated := map[string]any{}
			if !h.mergesInput {
				maps.Copy(updated, p.RawInput)
			}
			updated[h.commandField()] = wrapped
			mustMarshal(t, name, "rewrite", h.rewrite(updated))
		}
	})
}

func mustMarshal(t *testing.T, host, which string, doc map[string]any) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("%s: the %s reply does not marshal: %v", host, which, err)
	}
	if strings.TrimSpace(string(b)) == "" {
		t.Fatalf("%s: the %s reply marshalled to nothing", host, which)
	}
}
