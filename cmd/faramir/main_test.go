package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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

// The pasted value that must never be echoed back.  A credential in an error
// message is in the terminal, the scrollback and the agent's context, which is
// the mistake this file exists to prevent.
const pasted = "hunter2-correct-horse-battery"

// Every line readEnvFile refuses, and the part of the message that makes the
// refusal actionable.  Parsing here rather than letting the broker do it buys
// exactly one thing: a message that names the file and the line.  A message
// that does not is no better than the broker's.
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
		// "export NAME=..." is the habitual spelling for a file of environment
		// variables, and Cut on "=" turns it into a variable literally named
		// "export NAME".  The broker rejects that too, but by then the message
		// is about a name the operator never wrote.
		{name: "an export prefix", content: "export vault_router_password=secret://vault_router_password\n",
			wants: []string{"«path»"}},
		{name: "no name at all", content: "=secret://a/b\n"},
		// Last-wins is the usual env-file rule, but this file names credentials
		// for a fleet: a duplicate is a copy-paste slip, and silently picking
		// one of the two is how the wrong credential reaches a host.
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
			// Every refusal, not only the one about a pasted value: any of
			// these lines could hold one.
			if strings.Contains(err.Error(), pasted) {
				t.Errorf("the error echoed the pasted value: %v", err)
			}
		})
	}
}

// Repeating the same line is a merge artefact rather than an ambiguity: there
// is only one value it could mean.
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

// checkRef backs both --env and --env-file, so this invariant covers the two
// places a credential gets pasted by mistake.
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

// The account that works in the tree, in the order it is resolved.  A
// configuration manager escalates without sudo, so SUDO_USER is unset under
// Ansible and OPERATOR is what carries the name.
func TestOperatorNameResolution(t *testing.T) {
	// Whoever is running the tests, which is the last candidate and so the
	// answer whenever nothing else names one.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, flag, operator, sudoUser, want string }{
		{"the flag wins", "flagged", "env", "sudo", "flagged"},
		{"OPERATOR before SUDO_USER", "", "env", "sudo", "env"},
		{"SUDO_USER when that is all there is", "", "", "sudo", "sudo"},
		{"root is not an answer", "", "root", "sudo", "sudo"},
		// Nobody named: the caller is who this is about.  doctor run by hand is
		// the case, where not recognising them reports the operator as an
		// account nothing created.
		{"nothing at all falls back to the caller", "", "", "", current.Username},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OPERATOR", tc.operator)
			t.Setenv("SUDO_USER", tc.sudoUser)
			if got := operatorName(tc.flag); got != tc.want {
				t.Errorf("operatorName(%q) = %q, want %q", tc.flag, got, tc.want)
			}
		})
	}
}

// The guard sanctions the subcommands named in cli.Operator and denies those in
// cli.Internal, so a subcommand the dispatcher accepts but neither list names
// would have its arguments scanned: `faramir <it> --env A=secret://a` refused,
// for a command that is meant to take exactly that.
func TestEverySubcommandIsNamedForTheGuard(t *testing.T) {
	named := map[string]bool{}
	for _, name := range append(append([]string{}, cli.Operator...), cli.Internal...) {
		named[name] = true
	}
	// The dispatcher's own aliases: flags, not subcommands, and not something a
	// deny rule needs to reason about.
	for _, alias := range []string{"-h", "--help", "-V", "--version"} {
		named[alias] = true
	}

	for _, name := range dispatcherNames(t) {
		if !named[name] {
			t.Errorf("%q is a subcommand but is in neither cli.Operator nor cli.Internal", name)
		}
	}
}

// dispatcherNames reads the case labels out of run()'s switch.  Parsing the
// source rather than calling run() with each name: the provisioning subcommands
// want root and the daemons want a socket, so invoking them to find out whether
// they exist would be a test that installs things.
func dispatcherNames(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "case ")
		if !ok || !strings.HasSuffix(rest, ":") {
			continue
		}
		for _, label := range strings.Split(strings.TrimSuffix(rest, ":"), ",") {
			if name, err := strconv.Unquote(strings.TrimSpace(label)); err == nil {
				names = append(names, name)
			}
		}
	}
	if len(names) < 10 {
		t.Fatalf("found only %d case labels in run(); the switch was not parsed", len(names))
	}
	return names
}
