package secretref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The pasted value that must never be echoed back: an error message reaches the
// terminal, the scrollback and the agent's context.
const pasted = "hunter2-correct-horse-battery"

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

// checkEnv backs both --env and --env-file.
func TestNoRejectionEverQuotesTheValue(t *testing.T) {
	for _, name := range []string{"PW", "export PW", "", "1BAD"} {
		err := checkEnv(name, pasted)
		if err == nil {
			t.Errorf("checkEnv(%q, <literal>) accepted a non-ref", name)
			continue
		}
		if strings.Contains(err.Error(), pasted) {
			t.Errorf("checkEnv(%q, ...) echoed the value: %v", name, err)
		}
	}
}

func TestAWellFormedRefIsAccepted(t *testing.T) {
	if err := checkEnv("VAULT_PW", "faramir://home/router/admin"); err != nil {
		t.Errorf("a valid pair was rejected: %v", err)
	}
}

// A flag beats a file that names the same variable, which is what makes a file
// of defaults useful: the file is the fleet's, the flag is this command's. The
// file's other entries survive it.
func TestAnEnvFlagOverridesTheFileThatNamesIt(t *testing.T) {
	file := writeEnvFile(t, "ROUTER_PW=faramir://nope\nAPI=faramir://home/api/token\n")
	refs, err := EnvRefs([]string{file}, []string{"ROUTER_PW=faramir://home/router/admin"})
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
	_, err := EnvRefs([]string{first, second}, nil)
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
	refs, err := EnvRefs([]string{first, second}, nil)
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
	_, err := EnvRefs(nil, []string{"PW=faramir://a", "PW=faramir://b"})
	if err == nil {
		t.Fatal("two --env flags naming PW differently were not refused")
	}
	if !strings.Contains(err.Error(), "PW") {
		t.Errorf("the error does not name the conflicting variable: %v", err)
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
	for _, want := range []string{"_DEPLOY_TOKEN", "not a valid ref"} {
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

// A bare --env is the shortcut a bare --env-file line already was: the variable
// takes the ref of its own name, so `--env FOO` is `--env FOO=faramir://FOO`.
func TestABareEnvNamesTheRefOfThatName(t *testing.T) {
	refs, err := EnvRefs(nil, []string{"FOO", "BAR=faramir://home/router/admin"})
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
		if _, err := EnvRefs(nil, []string{name}); err == nil {
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
		err := checkEnv(ref, "faramir://"+ref)
		if err == nil {
			t.Errorf("checkEnv(%q) accepted a name no variable may have", ref)
			continue
		}
		for _, want := range []string{"--env NAME=faramir://" + ref, "is a ref"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("checkEnv(%q) does not offer %q: %v", ref, want, err)
			}
		}
	}
	// The long form itself is not this: the caller has already given the ref a
	// variable, and a name that is neither is still just a bad name.
	if err := checkEnv("V", "faramir://api/token"); err != nil {
		t.Errorf("the long form was refused: %v", err)
	}
	for _, name := range []string{"", "a b", "_x"} {
		err := checkEnv(name, "faramir://"+name)
		if err != nil && strings.Contains(err.Error(), "is a ref") {
			t.Errorf("checkEnv(%q) offered the long form for something that is no ref: %v",
				name, err)
		}
	}
}
