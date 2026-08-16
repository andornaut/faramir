package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/cli"
)

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "faramir.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnEnvFileYieldsItsRefs(t *testing.T) {
	refs, err := readEnvFile(writeEnvFile(t, `
# the fleet's credentials
vault_router_password=secret://vault_router_password

  vault_api_token = secret://home/api/token
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"vault_router_password": "secret://vault_router_password",
		"vault_api_token":       "secret://home/api/token",
	}
	if len(refs) != len(want) {
		t.Fatalf("got %d refs, want %d: %v", len(refs), len(want), refs)
	}
	for name, uri := range want {
		if refs[name] != uri {
			t.Errorf("%s = %q, want %q", name, refs[name], uri)
		}
	}
}

// The pasted value that must never be echoed back: an error message reaches the
// terminal, the scrollback and the agent's context.
const pasted = "hunter2-correct-horse-battery"

// Every line readEnvFile refuses, and the part of the message that makes it
// actionable.  Parsing here rather than at the broker provides exactly one thing: a
// message naming the file and the line.
func TestRefusedEnvFileLines(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		wants   []string // substrings the message must carry; "«path»" is the file
		why     string
	}{
		{name: "a line that is not NAME=value", content: "good=secret://a/b\nthis is not a pair\n",
			wants: []string{"«path»", ":2"}, why: "the message has to locate the problem"},
		{name: "a literal value", content: "PW=hunter2\n",
			wants: []string{"secret://"}, why: "the message has to say what was expected"},
		{name: "a pasted credential", content: "PW=" + pasted + "\n"},
		// Cut on "=" would name the variable "export NAME", and the broker's
		// refusal would then be about a name the operator never wrote.
		{name: "an export prefix", content: "export vault_router_password=secret://vault_router_password\n",
			wants: []string{"«path»"}},
		{name: "no name at all", content: "=secret://a/b\n"},
		// A duplicate is a copy-paste slip, and picking one of the two is how
		// the wrong credential reaches a host.
		{name: "a duplicate name", content: "PW=secret://a/b\nPW=secret://c/d\n",
			wants: []string{"PW"}, why: "the message has to name the duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeEnvFile(t, tc.content)
			_, err := readEnvFile(path)
			if err == nil {
				t.Fatalf("accepted %q", tc.content)
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), strings.ReplaceAll(want, "«path»", path)) {
					t.Errorf("message does not carry %q: %v (%s)", want, err, tc.why)
				}
			}
			// Any of these lines could hold one.
			if strings.Contains(err.Error(), pasted) {
				t.Errorf("the error echoed the pasted value: %v", err)
			}
		})
	}
}

// A merge artefact, not an ambiguity: one value it could mean.
func TestAnIdenticalRepeatIsAllowed(t *testing.T) {
	if _, err := readEnvFile(writeEnvFile(t, "PW=secret://a/b\nPW=secret://a/b\n")); err != nil {
		t.Errorf("an identical repeat was rejected: %v", err)
	}
}

func TestAMissingEnvFileIsReportedByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.env")
	_, err := readEnvFile(path)
	if err == nil {
		t.Fatal("a missing file was accepted")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file: %v", err)
	}
}

func TestAnEmptyFileYieldsNoRefs(t *testing.T) {
	refs, err := readEnvFile(writeEnvFile(t, "\n# only a comment\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("got %v, want no refs", refs)
	}
}

// checkRef backs both --env and --env-file.
func TestNoRejectionEverQuotesTheValue(t *testing.T) {
	for _, name := range []string{"PW", "export PW", "", "1BAD"} {
		err := checkRef(name, pasted)
		if err == nil {
			t.Errorf("checkRef(%q, <literal>) accepted a non-ref", name)
			continue
		}
		if strings.Contains(err.Error(), pasted) {
			t.Errorf("checkRef(%q, ...) echoed the value: %v", name, err)
		}
	}
}

func TestAWellFormedRefIsAccepted(t *testing.T) {
	if err := checkRef("VAULT_PW", "secret://home/router/admin"); err != nil {
		t.Errorf("a valid pair was rejected: %v", err)
	}
}

// -- the socket default ------------------------------------------------------

func TestTheSocketEnvVarOverridesTheDefault(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", "/tmp/custom.sock")
	if got := socketDefault(); got != "/tmp/custom.sock" {
		t.Errorf("got %q, want the value of FARAMIR_SOCKET", got)
	}
}

func TestAnEmptySocketEnvVarFallsBackToTheDefault(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", "")
	if got := socketDefault(); got == "" {
		t.Error("an empty FARAMIR_SOCKET left no socket path at all")
	}
}

// The account that works in the tree, in resolution order.  The flag is the
// only way to name one where SUDO_USER is unset.
func TestOperatorNameResolution(t *testing.T) {
	// The last candidate, and so the answer when nothing else names one.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// Unless the caller is root, which is refused at every position: run that
	// way with nothing set, no operator is named rather than one claimed.
	fallback := current.Username
	if fallback == "root" {
		fallback = ""
	}
	for _, tc := range []struct{ name, flag, sudoUser, want string }{
		{"the flag wins", "flagged", "sudo", "flagged"},
		{"SUDO_USER when that is all there is", "", "sudo", "sudo"},
		{"root is not an answer", "root", "sudo", "sudo"},
		// Nobody named, so the caller is who this is about: doctor run by hand would
		// otherwise report them as an account nothing created.
		{"nothing at all falls back to the caller", "", "", fallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_USER", tc.sudoUser)
			if got := operatorName(tc.flag); got != tc.want {
				t.Errorf("operatorName(%q) = %q, want %q", tc.flag, got, tc.want)
			}
		})
	}
}

// A subcommand the dispatcher accepts but neither cli.Operator nor cli.Internal
// names would have its arguments scanned.
func TestEverySubcommandIsNamedForTheGuard(t *testing.T) {
	named := map[string]bool{}
	for _, name := range append(append([]string{}, cli.Operator...), cli.Internal...) {
		named[name] = true
	}

	have := map[string]bool{}
	for _, c := range dispatcherNames(t) {
		have[c] = true
		if !named[c] {
			t.Errorf("%q is a subcommand but is in neither cli.Operator nor cli.Internal", c)
		}
	}
	// And the other way round: a name the lists still carry for a command that
	// no longer exists sanctions arguments that nothing scans.
	for name := range named {
		if !have[name] {
			t.Errorf("cli names %q, which is no longer a subcommand", name)
		}
	}
}

// dispatcherNames returns every subcommand the root carries.  Taken from the
// assembled command tree rather than from the source, so a command registered
// anywhere is seen.
func dispatcherNames(t *testing.T) []string {
	t.Helper()
	root := newRootCmd()
	// cobra adds `help` and `completion` while executing, not while building.
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("assembling the root: %s", err)
	}

	commands := root.Commands()
	names := make([]string, 0, len(commands))
	for _, c := range commands {
		names = append(names, c.Name())
	}
	if len(names) < 10 {
		t.Fatalf("found only %d subcommands; the root was not assembled", len(names))
	}
	return names
}

// Deny by default, at the last place a human's answer is read: only an explicit
// yes approves, so a typo, a stray word or an empty line refuses.
//
// "y" is among the refusals, not the approvals.  The watcher asks for `yes` and
// the keystroke this answer is guarded against is one the operator did not
// make: a tmux pane the agent can send-keys into, a tty the operator's account
// owns.  A tool that accepts less than it asks for is one whose prompt is not
// the rule.
func TestOnlyYesApproves(t *testing.T) {
	for _, line := range []string{"yes", "YES", " yes "} {
		if !approves(line) {
			t.Errorf("%q did not approve", line)
		}
	}
	for _, line := range []string{"no", "y", "Y", "", "\n", "y e s", "sure", "yes please", "ok", "1"} {
		if approves(line) {
			t.Errorf("%q approved an approval", line)
		}
	}
}

// A sentence is an answer, not a closed stdin: a reader that treats anything
// past the first word as end of input exits the watch, leaving the question to
// expire unanswered.
func TestAWordyAnswerIsReadAsAnAnswer(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	answers = bufio.NewReader(strings.NewReader("yes please\nyes\n\n"))
	for _, want := range []struct {
		approve bool
		ok      bool
	}{
		{false, true}, // "yes please" is not yes, and is still an answer
		{true, true},  // the next line is read, not eaten by the one before
		{false, true}, // a bare newline is a no
	} {
		approve, ok := readAnswer()
		if approve != want.approve || ok != want.ok {
			t.Errorf("readAnswer = (%v, %v), want (%v, %v)", approve, ok, want.approve, want.ok)
		}
	}
	// And only a closed stdin ends the watch.
	if _, ok := readAnswer(); ok {
		t.Error("readAnswer kept going past the end of its input")
	}
}

// The socket is systemd's and listens whether or not the daemon behind it
// started, so a broker that never becomes ready accepts the connection and
// answers nothing.  Without a bound the caller waits for ever, which for the
// coding agent is a tool call that never returns.
func TestTheWaitForAnAnswerIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request map[string]any
		want    time.Duration
	}{
		{"a command's own timeout, plus room to be killed and recorded",
			map[string]any{"op": "exec", "timeout_sec": 30}, 30*time.Second + execGrace},
		{"no timeout given, so the server's default decides and this is the outer bound",
			map[string]any{"op": "exec"}, execCeiling + execGrace},
		{"a request that runs no command", map[string]any{"op": "status"}, quickWait},
		{"nor does listing", map[string]any{"op": "list_secrets"}, quickWait},
		{"nor does a redact", map[string]any{"op": "redact", "text": "x"}, quickWait},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseWait(tc.request); got != tc.want {
				t.Errorf("responseWait = %s, want %s", got, tc.want)
			}
		})
	}
	// Every bound is finite, which is the whole point.
	for _, op := range []string{"exec", "status", "list_secrets", "redact", "approve"} {
		if wait := responseWait(map[string]any{"op": op}); wait <= 0 {
			t.Errorf("%s waits %s, which is not a bound", op, wait)
		}
	}
}

// `deny` needs no id: only one question is ever outstanding, so "the one that
// is waiting" names exactly one thing.  The asymmetry with approving is
// deliberate and worth holding in place.  Refusing something unseen is safe, and
// `approve` requires an id, because an approval that names no command is one
// nobody judged.
//
// Each stops at the root check rather than dialling a socket, which is enough to
// tell a usage error from an argument that was accepted.
func TestDenyNeedsNoIDAndApproveDoes(t *testing.T) {
	if code := cmdDeny(nil); code == 2 {
		t.Error("faramir deny = 2, want it accepted without an id")
	}
	if code := cmdDeny([]string{"9f2a1c"}); code == 2 {
		t.Error("faramir deny ID = 2, want an id accepted too")
	}
	if code := cmdApprove(nil); code != 2 {
		t.Errorf("faramir approve = %d, want 2: a yes has to name the command it is for", code)
	}
	if code := cmdApprove([]string{"9f2a1c"}); code == 2 {
		t.Error("faramir approve ID = 2, want it accepted")
	}
	// Listing takes no id at all: the verbs are their own commands now.
	if code := cmdApprovals([]string{"9f2a1c"}); code != 2 {
		t.Errorf("faramir approvals ID = %d, want 2: it lists and answers nothing", code)
	}
}

// A command that ran and failed says nothing of its own.  exitCodeError carries
// a status the command has already explained on its own stderr, so a second line
// naming it is faramir talking over the output the caller came for: a brokered
// command that exited 3 would otherwise have "Error: exit status 3" appended to
// what it printed.  The status still reaches the caller as the exit code.
func TestAFailedCommandPrintsNoErrorOfItsOwn(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	// `version` is reached without a broker, and its RunE is replaced with the
	// one thing under test: a status returned once the arguments are accepted.
	for _, c := range root.Commands() {
		if c.Name() == "version" {
			c.RunE = func(*cobra.Command, []string) error { return codeErr(3) }
		}
	}
	root.SetArgs([]string{"version"})
	if code := exitCode(root.Execute()); code != 3 {
		t.Errorf("exit = %d, want 3: the child's status is what the caller reads", code)
	}
	if out.Len() != 0 {
		t.Errorf("wrote %q, want nothing: the command has already explained itself", out.String())
	}
}

// A parse error names a flag the way the reader has to type it: two dashes for
// a long name, one for a single-letter shorthand.  Checked through the root,
// because what matters is the spelling that reaches the operator's stderr, and
// an operator told about "-socket" would try one faramir does not accept.
func TestAParseErrorSpellsAFlagTheWayItIsTyped(t *testing.T) {
	for _, c := range []struct{ name, arg, want string }{
		{"long name", "--bogus", "unknown flag: --bogus"},
		{"shorthand", "-Z", "unknown shorthand flag: 'Z' in -Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			root := newRootCmd()
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"status", c.arg})
			if code := exitCode(root.Execute()); code != 2 {
				t.Errorf("exit = %d, want 2 for a wrong invocation", code)
			}
			if !strings.Contains(out.String(), c.want) {
				t.Errorf("wrote %q, want it to contain %q", out.String(), c.want)
			}
		})
	}
}
