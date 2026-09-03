package guard

import "testing"

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
			// Through the decoder the hook uses, not into the struct: what a field
			// holds is decided there, and a test that unmarshalled straight into
			// the struct would pass over the spellings the decoder is what reads.
			p, err := decodeToolInput([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if got := commandOf(p); got != tc.want {
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
			p, err := decodeToolInput([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if _, denied := decide(commandOf(p)); !denied {
				t.Errorf("reading the age key was allowed when sent %s: %q", tc.name, commandOf(p))
			}
		})
	}
}

// One input namespace per host, so a field name means whatever the tool using
// it means. A tool taking a single argument spells `args` as a string, and a
// decoder that insisted on an array refused the call and told the operator that
// nothing in the tree was redacted, over a payload that was well formed.
func TestAToolInputIsReadWhateverTypeItsFieldsCarry(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"args as a single string",
			`{"tool_name":"Skill","tool_input":{"skill":"code-review","args":"roles/games"}}`,
			"'roles/games'"},
		{"args as an argv array",
			`{"tool_name":"Bash","tool_input":{"args":["ls","-la"]}}`, "'ls' '-la'"},
		{"args as neither",
			`{"tool_name":"Edit","tool_input":{"args":{"path":"/tmp/x"}}}`, ""},
		{"a field this reads carrying another tool's type",
			`{"tool_name":"Bash","tool_input":{"command":"ls","run_in_background":"yes"}}`, "ls"},
		{"a command that is not a string",
			`{"tool_name":"Bash","tool_input":{"command":{"argv":["ls"]}}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := decodeToolInput([]byte(tc.body))
			if err != nil {
				t.Fatalf("a well-formed payload was unreadable, which refuses the call "+
					"and reports the tree unredacted: %v", err)
			}
			if got := commandOf(p); got != tc.want {
				t.Errorf("commandOf = %q, want %q", got, tc.want)
			}
		})
	}
}

// The text of a single-string argument still reaches the rules. It is one word
// rather than a command, so it is quoted the way an argv element is, and a
// declared path named inside it is refused as the same path in an array is.
func TestASingleStringArgumentIsScanned(t *testing.T) {
	p, err := decodeToolInput([]byte(
		`{"tool_name":"Skill","tool_input":{"skill":"docs","args":"cat /etc/faramir/age.key"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, denied := decide(commandOf(p)); !denied {
		t.Errorf("the age key was allowed inside a single-string argument: %q", commandOf(p))
	}
}

// What the refusal is still for: the host's shape having changed, rather than
// one tool's field holding a type another tool's field does not.
func TestAPayloadThatIsNotThisHostsShapeIsStillUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"malformed JSON", `{"tool_name":"Bash",`},
		{"not an object at all", `"a string"`},
		{"a tool_input that is not an object", `{"tool_name":"Bash","tool_input":"ls -la"}`},
		{"a tool_name that is not a string", `{"tool_name":["Bash"],"tool_input":{"command":"ls"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeToolInput([]byte(tc.body)); err == nil {
				t.Error("read as a tool call, want the payload refused as unreadable")
			}
		})
	}
}
