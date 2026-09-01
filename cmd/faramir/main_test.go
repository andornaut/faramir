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
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/protocol"
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
vault_router_password=faramir://vault_router_password

  vault_api_token = faramir://home/api/token
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"vault_router_password": "faramir://vault_router_password",
		"vault_api_token":       "faramir://home/api/token",
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

// A name on its own asks for the ref of that name, so the one file that says
// which credentials a run needs does not say each name twice. Mixed with the
// mapping form, which is what a credential whose ref is named differently still
// needs.
func TestABareNameIsTheRefOfThatName(t *testing.T) {
	refs, err := readEnvFile(writeEnvFile(t, `
# the fleet's credentials
msmtp_password

  deploy_token
vault_api_token = faramir://home/api/token
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"msmtp_password":  "faramir://msmtp_password",
		"deploy_token":    "faramir://deploy_token",
		"vault_api_token": "faramir://home/api/token",
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

// The two forms must not disagree about one name: a bare name and a mapping of
// that name to another ref are two different credentials under one variable, and
// picking one is how the wrong one reaches a host.
func TestABareNameAndAMappingOfItDisagree(t *testing.T) {
	_, err := readEnvFile(writeEnvFile(t,
		"msmtp_password\nmsmtp_password=faramir://other\n"))
	if err == nil {
		t.Fatal("accepted a name given twice, as itself and as another ref")
	}
	if !strings.Contains(err.Error(), "msmtp_password") {
		t.Errorf("the message does not name the duplicate: %v", err)
	}
}

// A comment after an entry, which is what a shell and most dotenv readers take.
// It is the only place a bare line can say what a credential is for.
func TestATrailingCommentIsNotPartOfTheEntry(t *testing.T) {
	refs, err := readEnvFile(writeEnvFile(t,
		"msmtp_password   # the fleet's relay\n"+
			"ROUTER_PW=faramir://home/router/admin\t# the one behind the desk\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"msmtp_password": "faramir://msmtp_password",
		"ROUTER_PW":      "faramir://home/router/admin",
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

// The whitespace is what makes the cut safe. Without it the "#" is part of what
// was written, and truncating there would leave a ref that may exist and hold
// another credential, injected under a name whose line said otherwise.
func TestAHashInsideARefIsNotAComment(t *testing.T) {
	_, err := readEnvFile(writeEnvFile(t, "TOKEN=faramir://api#token\n"))

	// A "#" is not a character a ref may carry, so the line is refused. What
	// this holds is where it was refused and what it was called: the whole ref
	// as written. Cut at the "#", it would have read as faramir://api, which is
	// a ref that may exist and hold another credential.
	if err == nil {
		t.Fatal("a ref carrying a # was accepted")
	}
	if !strings.Contains(err.Error(), "faramir://api#token") {
		t.Errorf("the refusal names %q, want the ref as written: the # was cut", err)
	}
}

// The pasted value that must never be echoed back: an error message reaches the
// terminal, the scrollback and the agent's context.
const pasted = "hunter2-correct-horse-battery"

// Every line readEnvFile refuses, and the part of the message that makes it
// actionable. Parsing here rather than at the broker provides exactly one thing: a
// message naming the file and the line.
func TestRefusedEnvFileLines(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		wants   []string // substrings the message must carry; "«path»" is the file
		why     string
	}{
		{name: "a line that is not NAME=value", content: "good=faramir://a/b\nthis is not a pair\n",
			wants: []string{"«path»", ":2"}, why: "the message has to locate the problem"},
		{name: "a literal value", content: "PW=hunter2\n",
			wants: []string{"faramir://"}, why: "the message has to say what was expected"},
		{name: "a pasted credential", content: "PW=" + pasted + "\n"},
		// Cut on "=" would name the variable "export NAME", and the broker's
		// refusal would then be about a name the operator never wrote.
		{name: "an export prefix", content: "export vault_router_password=faramir://vault_router_password\n",
			wants: []string{"«path»"}},
		{name: "no name at all", content: "=faramir://a/b\n"},
		// A duplicate is a copy-paste slip, and picking one of the two is how
		// the wrong credential reaches a host.
		{name: "a duplicate name", content: "PW=faramir://a/b\nPW=faramir://c/d\n",
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
	//nolint:dupword // the repeated line is the fixture: this is the repeat
	if _, err := readEnvFile(writeEnvFile(t, "PW=faramir://a/b\nPW=faramir://a/b\n")); err != nil {
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
	if err := checkRef("VAULT_PW", "faramir://home/router/admin"); err != nil {
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

// The account that works in the tree, in resolution order. The flag is the
// only way to name one where neither $FARAMIR_OPERATOR nor SUDO_USER is set.
func TestOperatorNameResolution(t *testing.T) {
	// The last candidate, and so the answer when nothing else names one.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// Unless the caller is one this refuses at every position, root or a faramir
	// account: run that way with nothing set, no operator is named rather than
	// one claimed.
	refused := notTheOperator()
	fallback := current.Username
	if refused[fallback] {
		fallback = ""
	}
	for _, tc := range []struct{ name, flag, operator, sudoUser, want string }{
		{"the flag wins", "flagged", "brokered", "sudo", "flagged"},
		{"SUDO_USER when that is all there is", "", "", "sudo", "sudo"},
		{"root is not an answer", "root", "", "sudo", "sudo"},
		// A brokered command's sudo sets SUDO_USER to the executor, whose home holds
		// none of the operator's configuration. $FARAMIR_OPERATOR is the marker that
		// says so, written by the broker from the live config and carried to root by
		// the grant's env_file, so it outranks what sudo filled in.
		{"the broker's marker outranks SUDO_USER", "", "brokered", "sudo", "brokered"},
		{"and names the operator where sudo named the executor", "",
			"brokered", hostlayout.DefaultExecUser, "brokered"},
		// Without the marker there is nothing to correct SUDO_USER with, so the
		// service account falls through rather than being taken for a person: an
		// enrolment that believed it would chown a checkout to an account holding
		// nothing.
		{"a faramir account in SUDO_USER is not an answer", "", "",
			hostlayout.DefaultExecUser, fallback},
		{"nor is the broker's own", "", "", hostlayout.DefaultBrokerUser, fallback},
		{"nor the keeper's", "", "", hostlayout.DefaultKeeperUser, fallback},
		// Nobody named, so the caller is who this is about: doctor run by hand would
		// otherwise report them as an account nothing created.
		{"nothing at all falls back to the caller", "", "", "", fallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(protocol.OperatorEnv, tc.operator)
			t.Setenv("SUDO_USER", tc.sudoUser)
			if got := operatorName(refused, tc.flag); got != tc.want {
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

// The listing is one column of descriptions, and `help` and `completion` are
// cobra's: it writes "Help about any command", so a lowercase description
// beside that one reads as a command of a different kind rather than as one
// this project wrote. Sentence case throughout, cobra's own included, which is
// what nothing but this holds a new command to.
func TestEveryCommandIsDescribedInSentenceCase(t *testing.T) {
	root := newRootCmd()
	// cobra adds `help` and `completion` while executing, not while building.
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("assembling the root: %s", err)
	}

	checked := 0
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			checked++
			first, _ := utf8.DecodeRuneInString(sub.Short)
			switch {
			case sub.Short == "":
				t.Errorf("%s carries no description, so the listing has a blank row",
					sub.CommandPath())
			case !unicode.IsUpper(first):
				t.Errorf("%s is described as %q, which opens in lower case where "+
					"cobra's own do not", sub.CommandPath(), sub.Short)
			}
			walk(sub)
		}
	}
	walk(root)
	if checked == 0 {
		t.Fatal("the root carries no subcommands, so this asserts nothing")
	}
}

// dispatcherNames returns every subcommand the root carries. Taken from the
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

	// A command that groups others contributes its children rather than itself,
	// spelled the way cli.Operator spells them: the guard matches what a person
	// types, and nobody types a bare `faramir vault`. To the leaf, however deep,
	// a walk that stopped short leaving those children out of the list the
	// sanction is built from.
	var names []string
	var walk func(prefix string, c *cobra.Command)
	walk = func(prefix string, c *cobra.Command) {
		// cobra's own, and the only two whose children are not faramir's: the
		// shells `completion` generates for are not subcommands anybody names here.
		if c.Name() == "completion" || c.Name() == "help" {
			names = append(names, c.Name())
			return
		}
		name := strings.TrimSpace(prefix + " " + c.Name())
		children := c.Commands()
		if len(children) == 0 {
			names = append(names, name)
			return
		}
		for _, child := range children {
			walk(name, child)
		}
	}
	for _, c := range root.Commands() {
		walk("", c)
	}
	if len(names) < 10 {
		t.Fatalf("found only %d subcommands; the root was not assembled", len(names))
	}
	return names
}

// Deny by default, at the last place a human's answer is read: only an explicit
// y approves, so a typo, a stray word or a punctuation mark refuses. "yes" is
// among the refusals: one token approves, and a second spelling of it is a
// second thing to get wrong.
func TestOnlyYApproves(t *testing.T) {
	// The last two are what a terminal puts around an answer rather than part of
	// one: the newline it is read up to, and the carriage return of a CRLF ending.
	for _, line := range []string{"y", "Y", " y ", "y\n", "y\r\n"} {
		if !approves(line) {
			t.Errorf("%q did not approve", line)
		}
	}
	for _, line := range []string{"no", "n", "yes", "YES", "", "\n", "y e s", "sure", "y please", "ok", "1"} {
		if approves(line) {
			t.Errorf("%q approved an escalation", line)
		}
	}
}

// Only the edges are stripped, so nothing is edited down into an approval it did
// not spell: a line needing an unprintable byte removed from the middle of it to
// read as "y" was not somebody typing y.
func TestAnInteriorUnprintableIsNotEditedIntoAnApproval(t *testing.T) {
	for _, line := range []string{"y\x00e", "y\re", "y\x1bs", "y\x00es"} {
		if approves(line) {
			t.Errorf("%q approved an escalation", line)
		}
	}
}

// What holds nothing printable is not an answer and must not be counted as a
// no: an unanswered question is left to expire rather than being spent by a
// stray newline. A punctuation mark is an answer, and so a refusal: an
// operator who types "?" is owed the question closing.
func TestABlankLineIsNotAnAnswer(t *testing.T) {
	for _, line := range []string{"", "\n", "   \n", "\t\r\n", "\x1b\n"} {
		if answerOf(line) != "" {
			t.Errorf("%q was read as an answer", line)
		}
	}
	for _, line := range []string{"no\n", "y\n", "?\n"} {
		if answerOf(line) == "" {
			t.Errorf("%q was not read as an answer", line)
		}
	}
}

// A sentence is an answer, not a closed stdin: a reader that treats anything
// past the first word as end of input exits the watch, leaving the question to
// expire unanswered.
func TestAWordyAnswerIsReadAsAnAnswer(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	answers = bufio.NewReader(strings.NewReader("y please\n\ny\n"))
	terminal := readLines(palette{})
	for _, want := range []bool{
		false, // "y please" is not y, and is still an answer
		true,  // the blank line is asked again, and the y after it read
	} {
		line, state := terminal.answer(time.Now().Add(time.Minute))
		if state != answered {
			t.Fatalf("the wait ended in state %v, want an answer", state)
		}
		if approves(line) != want {
			t.Errorf("approves(%q) = %v, want %v", line, approves(line), want)
		}
	}
	// And only a closed stdin ends the watch.
	if _, state := terminal.answer(time.Now().Add(time.Minute)); state != stdinClosed {
		t.Errorf("the wait ended in state %v past the end of its input, want stdinClosed", state)
	}
}

// The socket is systemd's and listens whether or not the daemon behind it
// started, so a broker that never becomes ready accepts the connection and
// answers nothing. A request that runs no command, and a run with its own -t,
// are bounded tightly. A run with no -t defers to the broker, which enforces
// [command] max_timeout_sec the client cannot read: the client sets no ceiling
// that could fall below it and kill a within-policy run, so its wait is the
// largest a Duration holds. Every wait stays finite, which is what keeps a
// multiplied timeout from overflowing into a deadline already past.
func TestTheWaitForAnAnswerIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request map[string]any
		want    time.Duration
	}{
		{"a command's own timeout, plus room to be killed and recorded",
			map[string]any{"op": "run", "timeout_sec": 30}, 30*time.Second + execGrace},
		{"no timeout given, so the broker's own max decides and the client does not preempt it",
			map[string]any{"op": "run"}, time.Duration(maxWaitSeconds)*time.Second + execGrace},
		{"a request that runs no command", map[string]any{"op": "status"}, quickWait},
		{"nor does listing", map[string]any{"op": "refs"}, quickWait},
		{"nor does a redact", map[string]any{"op": "redact", "text": "x"}, quickWait},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseWait(tc.request); got != tc.want {
				t.Errorf("responseWait = %s, want %s", got, tc.want)
			}
		})
	}
	// Every bound is finite, which is the whole point.
	for _, op := range []string{"run", "status", "refs", "redact", "approve"} {
		if wait := responseWait(map[string]any{"op": op}); wait <= 0 {
			t.Errorf("%s waits %s, which is not a bound", op, wait)
		}
	}
}

// `deny` needs no id: only one question is ever outstanding. The asymmetry
// with approving is deliberate -- refusing something unseen is safe, and an
// escalation that names no command is one nobody judged. Each stops at the
// root check rather than dialling a socket, which is enough to tell a usage
// error from an argument that was accepted.
func TestRejectNeedsNoIDAndApproveDoes(t *testing.T) {
	if code := runCommand(newRejectCmd(), nil); code == 2 {
		t.Error("faramir sudo reject = 2, want it accepted without an id")
	}
	if code := runCommand(newRejectCmd(), []string{"9f2a1c"}); code == 2 {
		t.Error("faramir sudo reject ID = 2, want an id accepted too")
	}
	if code := runCommand(newApproveCmd(), nil); code != 2 {
		t.Errorf("faramir sudo approve = %d, want 2: a yes has to name the command it is for", code)
	}
	if code := runCommand(newApproveCmd(), []string{"9f2a1c"}); code == 2 {
		t.Error("faramir sudo approve ID = 2, want it accepted")
	}
	// Listing and watching take no id at all: the verbs are their own commands.
	if code := runCommand(newSudoListCmd(), []string{"9f2a1c"}); code != 2 {
		t.Errorf("faramir sudo ls ID = %d, want 2: it lists and answers nothing", code)
	}
	if code := runCommand(newSudoWatchCmd(), []string{"9f2a1c"}); code != 2 {
		t.Errorf("faramir sudo watch ID = %d, want 2: it answers from the terminal", code)
	}
}

// A command that ran and failed says nothing of its own. exitCodeError carries
// a status the command has already explained on its own stderr, so a second line
// naming it is faramir talking over the output the caller came for: a brokered
// command that exited 3 would otherwise have "Error: exit status 3" appended to
// what it printed. The status still reaches the caller as the exit code.
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
// a long name, one for a single-letter shorthand. Checked through the root,
// because what matters is the spelling that reaches the operator's stderr, and
// an operator told about "-env-file" would try one faramir does not accept.
func TestAParseErrorSpellsAFlagTheWayItIsTyped(t *testing.T) {
	for _, c := range []struct{ name, arg, want string }{
		{"long name", "--bogus", "unknown flag: --bogus"},
		{"shorthand", "-Z", "unknown shorthand flag: 'Z' in -Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// One buffer, and it cannot be two: cobra writes usage to OutOrStderr(),
			// which is stderr only while SetOut is unset, so a test that captures
			// stdout by setting it pulls the usage block into its own capture. That
			// stdout stays clean is asserted in check-disclose.sh, against the real
			// binary and real file descriptors.
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

// The line is returned as it was read, so a refusal can quote it. An answer
// nobody typed refuses a question exactly as one they did, and a refusal that
// does not say what it read cannot be told from the operator's own no.
func TestReadAnswerReturnsWhatItRead(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	answers = bufio.NewReader(strings.NewReader("\x1b[?62;c\n"))
	line, state := readLines(palette{}).answer(time.Now().Add(time.Minute))
	if state != answered {
		t.Fatalf("the wait ended in state %v, want an answer", state)
	}
	if line != "\x1b[?62;c\n" {
		t.Errorf("readAnswer = %q, want the line as it arrived", line)
	}
	if approves(line) {
		t.Error("a terminal's own reply approved an escalation")
	}
}

// A re-ask does not throw away what was typed against the prompt it is
// re-asking. The flush is for input that predates the question; after the first
// prompt there is none, and flushing again eats the answer to a blank line typed
// ahead of it.
func TestARetryKeepsWhatWasTypedAfterThePrompt(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	// One burst: a stray newline, then the answer behind it.
	answers = bufio.NewReader(strings.NewReader("\ny\n"))
	line, state := readLines(palette{}).answer(time.Now().Add(time.Minute))
	if state != answered || !approves(line) {
		t.Errorf("the wait gave (%q, %v), want the y behind the blank line", line, state)
	}
}

// The wait rides the received line, and only where it says something. A
// watcher already running is answered the moment a question is filed, so zero is
// the ordinary reading and its absence says as much. It is the other case the
// number is for: nobody was here yet. Past tense, because the line is printed
// once and the number is frozen at what it was then.
func TestTheWaitedCountIsPrintedOnlyWhenItSaysSomething(t *testing.T) {
	question := escalation.Question{
		ID: "9f2a1c", Prompt: "faramir: Approve this command to run as root? `true`",
		Cmd: "true", ExpiresInSec: 120,
		Received: "2026-08-20T20:21:44-04:00",
	}
	fresh, _ := captureStdout(t, func() int { printQuestion(question, palette{}); return 0 })
	if strings.Contains(fresh, "waited") {
		t.Errorf("a question nobody was late for reports a wait:\n%s", fresh)
	}
	// The zone token is not pinned: Go resolves the offset against wherever this
	// runs, so it is EDT on the machine that wrote this and UTC in CI. What is
	// asserted is the moment and the clock beside it.
	if !strings.Contains(fresh, "received 2026-08-20 20:21:44 ") ||
		!strings.Contains(fresh, "(expires 120s)") {
		t.Errorf("the moment it was asked, and the clock the answer is typed "+
			"against, are not both there:\n%s", fresh)
	}

	question.WaitingSec, question.ExpiresInSec = 40, 80
	late, _ := captureStdout(t, func() int { printQuestion(question, palette{}); return 0 })
	if !strings.Contains(late, "received 2026-08-20 20:21:44 ") ||
		!strings.Contains(late, "(expires 80s, waited 40s)") {
		t.Errorf("a question that sat for 40s does not say so on the received line:\n%s", late)
	}
	// One line, not two: the wait qualifies the clock rather than standing beside it.
	if strings.Contains(late, "\n  waited") {
		t.Errorf("the wait is still a line of its own:\n%s", late)
	}
}

// The timestamp is the broker's, in the zone it recorded it in, and a question
// carrying none or carrying nonsense still prints the rest: the line an operator
// answers against is the expiry, and dropping it over an unparseable stamp would
// take that with it.
func TestTheReceivedStampSurvivesABrokerThatSaidSomethingOdd(t *testing.T) {
	for stamp, want := range map[string]string{
		// An offset no machine running this is in, so the zone token is the offset
		// itself wherever the test runs. Go resolves an offset that matches the
		// local zone to its name instead, which is what makes this read like the
		// day heading `logs` prints, and what makes pinning a name here flaky.
		"2026-08-20T20:21:44+05:45": "received 2026-08-20 20:21:44 +0545 (expires 120s)",
		"":                          "received (unknown) (expires 120s)",
		"not-a-time":                "received not-a-time (expires 120s)",
	} {
		question := escalation.Question{ID: "9f2a1c", Cmd: "true", ExpiresInSec: 120, Received: stamp}
		out, _ := captureStdout(t, func() int { printQuestion(question, palette{}); return 0 })
		if !strings.Contains(out, want) {
			t.Errorf("Received=%q rendered without %q:\n%s", stamp, want, out)
		}
	}
}

// A question nobody answers ends the wait on its own clock, so the terminal
// stops asking about one the broker has already refused and the loop goes back
// to the poll. Without it the read holds the loop until somebody types, and a
// question raised in the meantime is not shown.
func TestTheWaitEndsWhenTheQuestionExpires(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	// A reader with nothing in it and no end, which is a terminal nobody types at.
	answers = bufio.NewReader(blockingReader{make(chan struct{})})

	start := time.Now()
	line, state := readLines(palette{}).answer(time.Now().Add(150 * time.Millisecond))
	if state != expired {
		t.Errorf("the wait ended in state %v with %q, want expired", state, line)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("the wait took %v, so it was not the question's clock that ended it", waited)
	}
}

// blockingReader never returns and never ends, which is what stdin is when the
// operator is not at the keyboard.
type blockingReader struct{ never chan struct{} }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.never
	return 0, io.EOF
}

// A flag beats a file that names the same variable, which is what makes a file
// of defaults useful: the file is the fleet's, the flag is this command's. The
// file's other entries survive it.
func TestAnEnvFlagOverridesTheFileThatNamesIt(t *testing.T) {
	file := writeEnvFile(t, "ROUTER_PW=faramir://nope\nAPI=faramir://home/api/token\n")
	refs, err := execRefs([]string{file}, []string{"ROUTER_PW=faramir://home/router/admin"})
	if err != nil {
		t.Fatal(err)
	}
	if refs["ROUTER_PW"] != "faramir://home/router/admin" {
		t.Errorf("ROUTER_PW = %q, want the flag's ref", refs["ROUTER_PW"])
	}
	if refs["API"] != "faramir://home/api/token" {
		t.Errorf("API = %q, want the file's other entry kept", refs["API"])
	}
}

// Two files naming one variable with two different refs is an ambiguity nothing
// resolves, so it is refused rather than silently picking one: that is how the
// wrong credential reaches a host. The same policy a name given twice inside one
// file gets, now across files.
func TestConflictingEnvFilesAreRefused(t *testing.T) {
	first := writeEnvFile(t, "PW=faramir://first\n")
	second := writeEnvFile(t, "PW=faramir://second\n")
	_, err := execRefs([]string{first, second}, nil)
	if err == nil {
		t.Fatal("two files naming PW differently were not refused")
	}
	if !strings.Contains(err.Error(), "PW") {
		t.Errorf("the error does not name the conflicting variable: %v", err)
	}
}

// An identical ref in two files is a merge artefact, not a conflict, so it
// passes, the same as an identical repeat inside one file.
func TestIdenticalEnvFilesArePermitted(t *testing.T) {
	first := writeEnvFile(t, "PW=faramir://home/router/admin\n")
	second := writeEnvFile(t, "PW=faramir://home/router/admin\n")
	refs, err := execRefs([]string{first, second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if refs["PW"] != "faramir://home/router/admin" {
		t.Errorf("PW = %q, want the ref both files name", refs["PW"])
	}
}

// Two --env flags naming one variable with two different refs is refused for the
// same reason two files are: neither takes on trust.
func TestConflictingEnvFlagsAreRefused(t *testing.T) {
	_, err := execRefs(nil, []string{"PW=faramir://a", "PW=faramir://b"})
	if err == nil {
		t.Fatal("two --env flags naming PW differently were not refused")
	}
	if !strings.Contains(err.Error(), "PW") {
		t.Errorf("the error does not name the conflicting variable: %v", err)
	}
}

// run's flags stop at the program name, so a colliding flag after it is the
// program's and is passed through, with or without a "--".
func TestRunDoesNotStealTheChildsFlags(t *testing.T) {
	c := newRunCmd()
	args := []string{"deploy.sh", "--quiet", "--env", "production", "-C", "/elsewhere"}
	if err := c.Flags().Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(c.Flags().Args(), " "); got != strings.Join(args, " ") {
		t.Errorf("run consumed the child's flags: rest = %q, want %q", got, strings.Join(args, " "))
	}
	if q, _ := c.Flags().GetBool("quiet"); q {
		t.Error("the child's --quiet was read as run's own")
	}
	if env, _ := c.Flags().GetStringArray("env"); len(env) != 0 {
		t.Errorf("the child's --env was read as run's own: %v", env)
	}
}

// run's own flags before the program name still parse, and the program name and
// everything after it are the child's.
func TestRunReadsItsOwnFlagsBeforeTheCommand(t *testing.T) {
	c := newRunCmd()
	if err := c.Flags().Parse([]string{"-C", "/work", "--quiet", "deploy.sh", "--env", "production"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if q, _ := c.Flags().GetBool("quiet"); !q {
		t.Error("run's own --quiet before the command was not read")
	}
	if cwd, _ := c.Flags().GetString("cwd"); cwd != "/work" {
		t.Errorf("cwd = %q, want /work", cwd)
	}
	if got := strings.Join(c.Flags().Args(), " "); got != "deploy.sh --env production" {
		t.Errorf("child args = %q, want %q", got, "deploy.sh --env production")
	}
}

// A bare name has to be a usable ref as well as a usable variable name: the two
// namespaces differ at the first character, an environment variable being
// allowed to open with an underscore where a ref is not. Blocked with the file
// and the line, which is what the bare form promises, rather than at the broker
// with the line long gone.
func TestABareNameThatCannotBeARefIsRefusedHere(t *testing.T) {
	_, err := readEnvFile(writeEnvFile(t, "_DEPLOY_TOKEN\n"))
	if err == nil {
		t.Fatal("a bare name that is not a usable ref was accepted")
	}
	for _, want := range []string{"_DEPLOY_TOKEN", "not a ref"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is %q, want it to name %q", err, want)
		}
	}
}

// And the ordinary bare name still works, or the check above would be refusing
// the form it exists to support.
func TestAnOrdinaryBareNameStillResolves(t *testing.T) {
	refs, err := readEnvFile(writeEnvFile(t, "MSMTP_PASSWORD\n"))
	if err != nil {
		t.Fatalf("an ordinary bare name was refused: %v", err)
	}
	if refs["MSMTP_PASSWORD"] != "faramir://MSMTP_PASSWORD" {
		t.Errorf("refs = %v", refs)
	}
}

// No two commands describe themselves the same way. A group and one of its
// subcommands sharing a line is the case this catches: `faramir reader` and
// `faramir reader ls` both read "Who can decrypt the managed store", so the
// listing gave the same answer to two different questions and neither said
// what it did that the other did not.
func TestNoTwoCommandsShareADescription(t *testing.T) {
	root := newRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("assembling the root: %s", err)
	}
	seen := map[string]string{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			// cobra writes its own for these two, and writes them once.
			if name := sub.Name(); name != "help" && name != "completion" {
				if first, dup := seen[sub.Short]; dup {
					t.Errorf("%s and %s are both described as %q",
						first, sub.CommandPath(), sub.Short)
				} else {
					seen[sub.Short] = sub.CommandPath()
				}
			}
			walk(sub)
		}
	}
	walk(root)
	if len(seen) < 20 {
		t.Fatalf("only %d description(s) collected; the root was not assembled", len(seen))
	}
}

// A bare --env is the shortcut a bare --env-file line already was: the variable
// takes the ref of its own name, so `--env FOO` is `--env FOO=faramir://FOO`.
func TestABareEnvNamesTheRefOfThatName(t *testing.T) {
	refs, err := execRefs(nil, []string{"FOO", "BAR=faramir://home/router/admin"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := refs["FOO"], "faramir://FOO"; got != want {
		t.Errorf("FOO = %q, want %q", got, want)
	}
	if got, want := refs["BAR"], "faramir://home/router/admin"; got != want {
		t.Errorf("BAR = %q, want %q", got, want)
	}
}

// The shortcut is not a way past either namespace: the word has to be a usable
// variable name and a ref a store can hold.
func TestABareEnvIsHeldToBothNamespaces(t *testing.T) {
	for _, name := range []string{"db/password", "_LEADING", "has space", "9", ""} {
		if _, err := execRefs(nil, []string{name}); err == nil {
			t.Errorf("--env %q was accepted", name)
		}
	}
}

// The short form names the variable and the ref with one word, so it can only
// serve a ref whose name is also a name a variable may have. Most are not:
// `refs` prints faramir://api/token, and api/token is the obvious thing to
// type. Being told it is not a usable variable name is true and leaves nowhere
// to go, the long form being what serves it.
func TestABareRefThatCannotBeAVariableNameNamesTheLongForm(t *testing.T) {
	for _, ref := range []string{"api/token", "a-b", "1abc", "a.b"} {
		err := checkRef(ref, "faramir://"+ref)
		if err == nil {
			t.Errorf("checkRef(%q) accepted a name no variable may have", ref)
			continue
		}
		for _, want := range []string{"--env NAME=faramir://" + ref, "is a ref"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("checkRef(%q) does not offer %q: %v", ref, want, err)
			}
		}
	}
	// The long form itself is not this: the caller has already given the ref a
	// variable, and a name that is neither is still just a bad name.
	if err := checkRef("V", "faramir://api/token"); err != nil {
		t.Errorf("the long form was refused: %v", err)
	}
	for _, name := range []string{"", "a b", "_x"} {
		err := checkRef(name, "faramir://"+name)
		if err != nil && strings.Contains(err.Error(), "is a ref") {
			t.Errorf("checkRef(%q) offered the long form for something that is no ref: %v",
				name, err)
		}
	}
}

// writeAgentUserConfig is a config recording one operator, for the resolution a
// command that rewrites the config uses.
func writeAgentUserConfig(t *testing.T, agentUser string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	body := "[server]\n"
	if agentUser != "" {
		body += "agent_user = \"" + agentUser + "\"\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// What `block add` and `link add` resolve the operator to. They rewrite the whole
// config, so one that resolved it afresh would rename the host's owner as a side
// effect: a brokered `sudo faramir block add` has SUDO_USER set to the executor,
// and recording that account renders every path rule against its home.
func TestARewriteKeepsTheRecordedOperator(t *testing.T) {
	for _, tc := range []struct{ name, recorded, operator, sudoUser, want string }{
		{"the recorded operator wins over SUDO_USER", "op", "", "someoneelse", "op"},
		// The case this exists for.
		{"and over the executor a brokered sudo names", "op", "", hostlayout.DefaultExecUser, "op"},
		// Ahead of the marker too: the marker says who the host belongs to, which is
		// what the config already recorded, so they agree unless the config is what
		// went wrong, and this command is not the one that repairs it.
		{"and over the broker's own marker", "op", "brokered", hostlayout.DefaultExecUser, "op"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(protocol.OperatorEnv, tc.operator)
			t.Setenv("SUDO_USER", tc.sudoUser)
			got := recordedOperator(writeAgentUserConfig(t, tc.recorded))
			if got != tc.want {
				t.Errorf("recordedOperator = %q, want %q", got, tc.want)
			}
		})
	}
}

// An install whose config records nothing is one `init` has not finished, so
// there is no recorded answer to prefer and this resolves as everything else
// does. Held here because the fallback is what a host mid-provision depends on.
func TestARewriteFallsBackWhereNothingIsRecorded(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	t.Setenv("SUDO_USER", "sudo")
	if got := recordedOperator(writeAgentUserConfig(t, "")); got != "sudo" {
		t.Errorf("recordedOperator = %q, want the resolved %q", got, "sudo")
	}
}

// A config recording one of faramir's own accounts is the damage this change
// prevents, and a host that already carries it must not have it preserved.
func TestARewriteDoesNotKeepAServiceAccountAsTheOperator(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	t.Setenv("SUDO_USER", "op")
	if got := recordedOperator(writeAgentUserConfig(t, hostlayout.DefaultExecUser)); got != "op" {
		t.Errorf("recordedOperator = %q, want %q: a recorded service account is not "+
			"an operator to keep", got, "op")
	}
}

// The refusal set is this host's accounts rather than the compiled-in names, so
// an install that renamed one still refuses it. A default list is right about a
// default install and silently wrong here, and wrong means recording a service
// account as the operator.
func TestARenamedServiceAccountIsStillNotTheOperator(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	// What a host installed with `faramir init --exec-user` carries. The set is a
	// parameter for exactly this: no test can rename an account on the machine it
	// runs on.
	renamed := map[string]bool{"root": true, "faramir-runner": true}
	t.Setenv("SUDO_USER", "faramir-runner")
	if got := operatorName(renamed, ""); got == "faramir-runner" {
		t.Error("a renamed executor account was taken for the operator")
	}
	// And the compiled-in name is not refused on such a host, there being no
	// account of that name to refuse: the set says what this install has.
	t.Setenv("SUDO_USER", hostlayout.DefaultExecUser)
	if got := operatorName(renamed, ""); got != hostlayout.DefaultExecUser {
		t.Errorf("operatorName = %q, want %q: the default name is not this host's "+
			"executor, so it is an ordinary account here", got, hostlayout.DefaultExecUser)
	}
}

// What notTheOperator reads. Held because the whole point of the change is that
// this comes off the units rather than out of the binary, and a set missing an
// account is one that records it as the operator.
func TestTheRefusalSetCarriesRootAndEveryServiceAccount(t *testing.T) {
	refused := notTheOperator()
	if !refused["root"] {
		t.Error("root is not refused")
	}
	for _, account := range hostunit.InstalledAccounts() {
		if !refused[account] {
			t.Errorf("%q is installed as a service account and is not refused", account)
		}
	}
	if len(refused) != len(hostunit.InstalledAccounts())+1 {
		t.Errorf("the set holds %d entries, want root plus the %d service accounts",
			len(refused), len(hostunit.InstalledAccounts()))
	}
}

// `init` writes the units, so on a first install there are none to read and
// InstalledAccounts can only offer the compiled-in names. The accounts that run
// is naming have to join them, or a host installed with --exec-user would not
// refuse the account it is about to create.
func TestInitRefusesTheAccountsItIsNaming(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	t.Setenv("SUDO_USER", "")
	refused := notTheOperator("faramir-runner", "", "")
	if !refused["faramir-runner"] {
		t.Error("an account this run names is not refused")
	}
	if !refused["root"] {
		t.Error("root is not refused")
	}
	// An empty name is a flag nobody passed, not an account called "".
	if refused[""] {
		t.Error("the empty string is refused, so a flag left out names an account")
	}
	// And the installed names are still there beside them.
	for _, account := range hostunit.InstalledAccounts() {
		if !refused[account] {
			t.Errorf("%q is installed and is not refused", account)
		}
	}
}

// A refusal raised before the broker is contacted goes to the real os.Stderr.
// Past PersistentPreRunE the root command silences what a RunE returns, so a
// message written to cobra's own writer or returned as a usage error arrives
// nowhere and the caller is given a silent exit 2. The fd is captured rather
// than cobra's writer for that reason: the mistake this catches is the one that
// looks right in a test using SetErr.
func TestAPreBrokerRefusalReachesTheRealStderr(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	root := newRootCmd()
	root.SetArgs([]string{"run", "-t", "nonsense", "--", "echo", "hi"})
	code := exitCode(root.Execute())
	_ = w.Close()
	os.Stderr = old
	msg, _ := io.ReadAll(r)

	if code != 2 {
		t.Errorf("exit = %d, want 2 for an unparseable --timeout", code)
	}
	if !strings.Contains(string(msg), "--timeout") {
		t.Errorf("stderr = %q, want it to name the flag the caller has to retype", msg)
	}
}

// A working directory deleted from under the process is refused here rather
// than sent short: the broker has no default, so a request naming no directory
// comes back refused a round trip later saying less.
func TestACallerWithNoDirectoryIsRefusedBeforeTheBroker(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	_, err := resolveCwd("")
	if err == nil {
		t.Fatal("a deleted working directory was accepted, leaving the broker to refuse it")
	}
	if !strings.Contains(err.Error(), "-C") {
		t.Errorf("the refusal is %q, and names no flag, so a caller reading it "+
			"does not know what answers it", err)
	}
}

// A relative -C is the caller's directory plus that path, never the broker's:
// the broker runs from a directory of its own, so an unresolved relative path
// is the one place a caller could name a directory and be given another.
func TestARelativeCwdResolvesAgainstTheCaller(t *testing.T) {
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cwd  string
		want string
	}{
		{name: "absolute is untouched", cwd: "/work", want: "/work"},
		{name: "empty is the caller's own", cwd: "", want: here},
		{name: "dot is the caller's own", cwd: ".", want: here},
		{name: "relative hangs off it", cwd: "relative/dir",
			want: filepath.Join(here, "relative/dir")},
		// Cleaned on the way, because the broker compares what it is given
		// against a real directory and a dotted spelling of one is a spelling.
		{name: "a dotted spelling is cleaned", cwd: "sub/../other",
			want: filepath.Join(here, "other")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCwd(tc.cwd)
			if err != nil {
				t.Fatalf("resolveCwd(%q): %v", tc.cwd, err)
			}
			if got != tc.want {
				t.Errorf("resolveCwd(%q) = %q, want %q", tc.cwd, got, tc.want)
			}
		})
	}
}
