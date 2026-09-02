package protocol

import (
	"encoding/json"
	"testing"

	"github.com/andornaut/faramir/internal/secretref"
)

// Parse is the first thing a request meets, on a socket any account in the
// client group can reach. Whatever arrives, it answers rather than panicking,
// and what it accepts satisfies the rules the rest of the broker assumes.
func FuzzParseAnswersWhateverArrives(f *testing.F) {
	f.Add(`{"op":"run","cmd":["/bin/echo","x"],"version":"dev"}`)
	f.Add(`{"op":"redact","text":"x","more":true,"version":"dev"}`)
	f.Add(`{"op":"run","cmd":["x"],"env":{"A":"faramir://a/b"},"version":"dev"}`)
	f.Add(`{"op":"escalate","id":"x","approve":true,"version":"dev"}`)
	f.Add(`{"cmd":[],"env":{"":""},"timeout_sec":-1,"version":"dev"}`)

	f.Fuzz(func(t *testing.T, body string) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Skip()
		}
		req, err := Parse(payload)
		if err != nil {
			if req != nil {
				t.Fatalf("a refused request came back with a value: %+v", req)
			}
			return
		}
		if req == nil {
			t.Fatal("Parse returned no request and no error")
		}
		for name := range req.EnvRefs {
			if !secretref.ValidEnvName(name) {
				t.Fatalf("accepted an environment name Parse's own check refuses: %q", name)
			}
		}
		if req.TimeoutSec < 0 {
			t.Fatalf("accepted a negative timeout: %d", req.TimeoutSec)
		}
		if req.Op == "" {
			t.Fatal("accepted a request with no op")
		}
	})
}
