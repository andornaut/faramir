package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
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

// The point of parsing here rather than letting the broker do it is that the
// message can name the file and the line.  A message that does not is no better
// than the broker's.
func TestAMalformedLineNamesTheFileAndLine(t *testing.T) {
	path := writeEnvFile(t, "good=secret://a/b\nthis is not a pair\n")
	_, err := readEnvFile(path)
	if err == nil {
		t.Fatal("a line that is not NAME=value was accepted")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), ":2") {
		t.Errorf("the error does not locate the problem: %v", err)
	}
}

func TestAValueThatIsNotASecretRefIsRejected(t *testing.T) {
	_, err := readEnvFile(writeEnvFile(t, "PW=hunter2\n"))
	if err == nil {
		t.Fatal("a literal value was accepted as a ref")
	}
	if !strings.Contains(err.Error(), "secret://") {
		t.Errorf("the error does not say what was expected: %v", err)
	}
}

// A pasted value is the mistake this file exists to prevent, so the error must
// not echo it back into the terminal and the scrollback.
func TestRejectingALiteralValueDoesNotEchoIt(t *testing.T) {
	const pasted = "hunter2-correct-horse-battery"
	_, err := readEnvFile(writeEnvFile(t, "PW="+pasted+"\n"))
	if err == nil {
		t.Fatal("a literal value was accepted as a ref")
	}
	if strings.Contains(err.Error(), pasted) {
		t.Errorf("the error echoed the pasted value: %v", err)
	}
}

// "export NAME=..." is the habitual spelling for a file of environment
// variables, and Cut on "=" turns it into a variable literally named
// "export NAME".  The broker rejects that, but by then the message is about a
// name the operator never wrote.
func TestAnExportPrefixIsRejectedWhereItCanBeExplained(t *testing.T) {
	path := writeEnvFile(t, "export vault_router_password=secret://vault_router_password\n")
	_, err := readEnvFile(path)
	if err == nil {
		t.Fatal("an export prefix was accepted")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file: %v", err)
	}
}

func TestAnEmptyNameIsRejected(t *testing.T) {
	if _, err := readEnvFile(writeEnvFile(t, "=secret://a/b\n")); err == nil {
		t.Error("a line with no name was accepted")
	}
}

// Last-wins is the usual env-file rule, but this file names credentials for a
// fleet: a duplicate is a copy-paste slip, and silently picking one of the two
// is how the wrong credential reaches a host.
func TestADuplicateNameIsRejected(t *testing.T) {
	path := writeEnvFile(t, "PW=secret://a/b\nPW=secret://c/d\n")
	_, err := readEnvFile(path)
	if err == nil {
		t.Fatal("a duplicate name was accepted")
	}
	if !strings.Contains(err.Error(), "PW") {
		t.Errorf("the error does not name the duplicate: %v", err)
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
	const pasted = "hunter2-correct-horse-battery"
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
