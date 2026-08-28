package guard

import (
	"encoding/json"
	"testing"
)

// What decide() is given. Some clients send the command as one string and some
// as an argv array; a rule only sees what commandOf joined, so an unread field
// is a command nobody scanned.

func TestCommandOfReadsBothSpellingsOfAToolInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"a command string", `{"tool_input":{"command":"ls -la"}}`, "ls -la"},
		{"an argv array", `{"tool_input":{"args":["ls","-la"]}}`, "'ls' '-la'"},
		{"both, command first", `{"tool_input":{"command":"sh -c","args":["ls"]}}`, "sh -c 'ls'"},
		{"neither", `{"tool_input":{}}`, ""},
		{"empty argv entries are dropped", `{"tool_input":{"args":["ls","","-la"]}}`, "'ls' '-la'"},
		{"non-string argv entries are ignored", `{"tool_input":{"args":["ls",7,null,true,"-la"]}}`, "'ls' '-la'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p payload
			if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
				t.Fatal(err)
			}
			if got := commandOf(&p); got != tc.want {
				t.Errorf("commandOf = %q, want %q", got, tc.want)
			}
		})
	}
}

// The rules run over commandOf's output, so a denied command has to be denied in
// whichever spelling the client used. Reaching decide() through the payload is
// what ties the two together: testing decide() alone leaves the argv path free.
func TestADeniedCommandIsDeniedInEitherSpelling(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"as a command string", `{"tool_input":{"command":"cat /etc/faramir/age.key"}}`},
		{"as an argv array", `{"tool_input":{"args":["cat","/etc/faramir/age.key"]}}`},
		{"split across both", `{"tool_input":{"command":"cat","args":["/etc/faramir/age.key"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p payload
			if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
				t.Fatal(err)
			}
			if _, denied := decide(commandOf(&p)); !denied {
				t.Errorf("reading the age key was allowed when sent %s: %q", tc.name, commandOf(&p))
			}
		})
	}
}
