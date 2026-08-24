package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func load(t *testing.T, text string) (*Config, error) {
	t.Helper()
	var raw map[string]any
	if err := toml.Unmarshal([]byte(text), &raw); err != nil {
		t.Fatalf("toml: %v", err)
	}
	return fromMap(raw, "<test>")
}

const minimal = `
[command]
timeout_sec = 600
`

func TestMinimalConfigLoads(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	// Defaults the file did not set.
	if cfg.Ssh.AgentSocket != "/run/faramir/ssh-agent.sock" {
		t.Errorf("agent_socket = %q", cfg.Ssh.AgentSocket)
	}
	if cfg.Command.MaxTimeoutSec != 3600 {
		t.Errorf("max_timeout_sec = %d", cfg.Command.MaxTimeoutSec)
	}
}

// The escalation server is off unless the config says otherwise, which is what makes the
// whole arrangement additive: no secret_file, so no socket, no injection and
// nothing for a brokered command to ask.
func TestEscalationIsOffUnlessConfigured(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sudo.ExecUser != "" {
		t.Errorf("exec_user = %q, want unset", cfg.Sudo.ExecUser)
	}
	// The rest still has values, describing where things would go if one were
	// ever set.
	if cfg.Sudo.PamService == "" || cfg.Sudo.TimeoutSec == 0 {
		t.Errorf("escalation defaults are incomplete: %+v", cfg.Sudo)
	}
}

// Nothing announces a pending request by default: `faramir sudo approve` is where a
// question is seen and answered. A notifier that names neither the command nor
// the question is refused, since it would say only that something is waiting.
func TestANotifierThatSaysNothingIsRefused(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sudo.NotifyCommand) != 0 {
		t.Errorf("notify_command = %q, want nothing by default", cfg.Sudo.NotifyCommand)
	}
	_, err = load(t, minimal+"[sudo]\nnotify_command = [\"wall\", \"something happened\"]\n")
	if err == nil {
		t.Fatal("accepted a notifier that names neither the command nor the question")
	}
	if !strings.Contains(err.Error(), "notify_command") {
		t.Errorf("error does not name the key: %v", err)
	}
	// One that names either is fine.
	if _, err := load(t, minimal+"[sudo]\nnotify_command = [\"wall\", \"{prompt}\"]\n"); err != nil {
		t.Errorf("refused a usable notifier: %v", err)
	}
}

// timeout_sec is bounded at both ends, and the ceiling is not a taste: the PAM
// helper derives its own deadline from MaxSudoTimeoutSec, so a question the
// broker would hold for longer than that is one the helper would abandon while
// it was still open, and the operator's yes would land on a sudo that had
// already gone. The two constants cannot drift, so this is what keeps the
// relationship between them true.
func TestSudoTimeoutIsBoundedAtBothEnds(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"zero", "[sudo]\ntimeout_sec = 0\n"},
		{"past the ceiling", fmt.Sprintf("[sudo]\ntimeout_sec = %d\n", MaxSudoTimeoutSec+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, minimal+tc.body)
			if err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), "timeout_sec") {
				t.Errorf("error does not name the key: %v", err)
			}
		})
	}
	// The ceiling itself loads: it is the bound, not the first refusal.
	cfg, err := load(t, minimal+fmt.Sprintf("[sudo]\ntimeout_sec = %d\n", MaxSudoTimeoutSec))
	if err != nil {
		t.Fatalf("refused the ceiling itself: %v", err)
	}
	if cfg.Sudo.TimeoutSec != MaxSudoTimeoutSec {
		t.Errorf("timeout_sec = %d, want %d", cfg.Sudo.TimeoutSec, MaxSudoTimeoutSec)
	}
}

// A mistyped key is named, not ignored, and so is a retired one: a config still
// setting a key that is gone is asking for a behaviour that is not there, and
// reading as though it were. Where something replaced it, the message names
// that too, the operator's next move being to write the replacement.
func TestUnknownKeysAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		wants      []string
	}{
		{name: "a misspelling in [server]", text: minimal + "\n[server]\nsoket_path = \"/x\"\n"},
		{name: "a singular where the key is plural", text: "[command]\nterm_col = 80\n"},
		{name: "the retired [command] default_cwd", text: "[command]\ndefault_cwd = \"/t\"\n",
			wants: []string{"default_cwd"}},
		// The numeric spelling of a caller: allowed_uids said what allowed_group
		// says, in a form that stopped being true once an account was renumbered.
		{name: "allowed_uids, replaced by allowed_group",
			text:  minimal + "\n[server]\nallowed_uids = [1000]\n",
			wants: []string{"allowed_group"}},
		// The executor's own cap is gone, the broker holding a [server]
		// concurrency slot for the whole of each child and being the only client
		// this socket admits.
		{name: "a concurrency of the executor's own",
			text:  minimal + "\n[executor]\nconcurrency = 8\n",
			wants: []string{"concurrency"}},
		// The broker no longer grades a secret's strength, so the two keys that did
		// are refused rather than quietly ignored.
		{name: "min_unique_chars, a strength threshold",
			text:  minimal + "\n[secret]\nmin_unique_chars = 4\n",
			wants: []string{"min_length"}},
		{name: "min_entropy_bits_per_char, likewise",
			text:  minimal + "\n[secret]\nmin_entropy_bits_per_char = 1.5\n",
			wants: []string{"min_length"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.text)
			if err == nil || !strings.Contains(err.Error(), "unknown key") {
				t.Fatalf("err = %v", err)
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the message does not name %q: %v", want, err)
				}
			}
		})
	}
}

// [secret] for [secret], or [command] for [command]: a section nobody reads is a
// setting that looks applied and is not. Named, with the sections that exist.
func TestUnknownSectionsAreRefused(t *testing.T) {
	// Spelled with string concatenation so a future rename pass cannot quietly
	// turn these deliberate mistakes back into the valid names they are the
	// mistake for.
	for _, mistake := range []string{
		"\n[" + "secrets" + "]\nmin_length = 12\n",
		"\n[" + "exec" + "]\ntimeout_sec = 30\n",
		"\n[" + "escalation" + "]\ntimeout_sec = 30\n",
	} {
		err := func() error { _, err := load(t, minimal+mistake); return err }()
		if err == nil {
			t.Errorf("%q was accepted", mistake)
			continue
		}
		for _, want := range []string{"unknown section", "command", "secret"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: message does not mention %q: %v", mistake, want, err)
			}
		}
	}
}

// Each of these has a concrete consequence: a broker that panics on startup,
// refuses every request as busy, or kills every command as it starts.
func TestOutOfRangeValuesAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"negative max_concurrency", minimal + "\n[server]\nmax_concurrency = -1\n"},
		{"zero max_concurrency", minimal + "\n[server]\nmax_concurrency = 0\n"},
		{"zero max_request_bytes", minimal + "\n[server]\nmax_request_bytes = 0\n"},
		{"zero timeout_sec", "[command]\ntimeout_sec = 0\n"},
		{"zero max_timeout_sec", "[command]\nmax_timeout_sec = 0\n"},
		{"zero max_output_bytes", "[command]\nmax_output_bytes = 0\n"},
		{"min_length under the floor", minimal + "\n[secret]\nmin_length = 5\n"},
		{"zero concurrency", "[command]\nconcurrency = 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(t, tc.text); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// A max below the default replaces it for every command rather than capping it.
func TestMaxTimeoutBelowDefaultIsRefused(t *testing.T) {
	_, err := load(t, "[command]\ntimeout_sec = 600\nmax_timeout_sec = 60\n")
	if err == nil || !strings.Contains(err.Error(), "max_timeout_sec") {
		t.Fatalf("err = %v", err)
	}
}

// No tunable takes zero, and this one is why the rule exists: zero is the
// signal an unset flag leaves, so a key that accepted it could not be told from
// one nobody typed, and an operator who asked for it would silently get the
// install's old value back.
func TestNoTunableTakesZero(t *testing.T) {
	// Whole configs rather than minimal+body: minimal already opens [command],
	// and a second header is a duplicate table TOML refuses before any of these
	// rules is reached.
	for _, body := range []string{
		"[secret]\nmin_length = 0\n",
		"[command]\ntimeout_sec = 0\n",
		"[command]\nconcurrency = 0\n",
		"[sudo]\ntimeout_sec = 0\n",
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("accepted a zero: %s", body)
		}
	}
}

func TestScalarWhereTableExpected(t *testing.T) {
	_, err := load(t, "server = \"0660\"\n"+minimal)
	if err == nil || !strings.Contains(err.Error(), "expected a [server] table") {
		t.Fatalf("err = %v", err)
	}
}

// How the keeper invokes sops is derived, and no key reaches it: a second way
// to invoke it would be a second thing that could be pointed elsewhere, by the
// account holding the age key.
func TestTheDecryptCommandIsDerived(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	want := "sops --output-type json --decrypt {file}"
	if strings.Join(cfg.Secret.DecryptCommand, " ") != want {
		t.Errorf("decrypt_command = %v", cfg.Secret.DecryptCommand)
	}
}

// env PATH decides which file a bare cmd[0] resolves to, and the broker
// resolves it on behalf of a child that runs in the request's directory, not the
// broker's. A component a shell would read as "here" therefore names two
// different directories, so it is refused at load: the broker does not start,
// rather than running a file nobody named.
func TestBaseEnvPathMustBeAbsolute(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		// wants is a substring of the refusal; "" means the config must load.
		wants string
	}{
		{"absolute components are fine", "/usr/bin:/bin", ""},
		{"a single absolute component is fine", "/usr/bin", ""},
		{"a leading empty component", ":/usr/bin", "env PATH"},
		{"a trailing empty component", "/usr/bin:", "env PATH"},
		{"an empty component in the middle", "/usr/bin::/bin", "env PATH"},
		{"an explicit dot", "/usr/bin:.", "env PATH"},
		{"a relative directory", "/usr/bin:vendor/bin", "env PATH"},
		// Its own message: an empty string is not a component anybody wrote, and
		// setting PATH to nothing is not the same as leaving it out.
		{"emptied", "", "sets PATH to nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := load(t, "[command]\nenv = { PATH = \""+tc.path+"\" }\n")
			if tc.wants != "" {
				if err == nil {
					t.Fatalf("PATH %q was accepted; env = %v", tc.path, cfg.Command.Env)
				}
				if !strings.Contains(err.Error(), tc.wants) {
					t.Errorf("error does not say %q: %v", tc.wants, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("PATH %q was refused: %v", tc.path, err)
			}
			if cfg.Command.Env["PATH"] != tc.path {
				t.Errorf("PATH = %q, want %q", cfg.Command.Env["PATH"], tc.path)
			}
		})
	}
}

// The compiled-in default has to pass its own check.
func TestTheDefaultPathIsAccepted(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command.Env["PATH"] != defaultPATH {
		t.Errorf("PATH = %q, want the compiled-in default", cfg.Command.Env["PATH"])
	}
}

// The env merges over the built-in table rather than replacing it: a file that
// sets one variable must not take PATH away and leave the broker unable to
// resolve a bare program name.
func TestNamingOneVariableKeepsTheRest(t *testing.T) {
	for _, body := range []string{
		"[command]\nenv = { TERM = \"dumb\" }\n",
		"[command.env]\nANSIBLE_NOCOWS = \"1\"\n",
	} {
		cfg, err := load(t, body)
		if err != nil {
			t.Errorf("%q was refused: %v", body, err)
			continue
		}
		if cfg.Command.Env["PATH"] != defaultPATH {
			t.Errorf("%q took PATH away: %q", body, cfg.Command.Env["PATH"])
		}
	}
	// And the one it named is there beside it.
	cfg, err := load(t, "[command.env]\nANSIBLE_NOCOWS = \"1\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command.Env["ANSIBLE_NOCOWS"] != "1" {
		t.Errorf("the named variable is missing: %v", cfg.Command.Env)
	}
}

// `status` and `--check` report which files were read. With one config file
// that is a list of one, and it has to be filled in: an empty answer to "which
// files were read" reads as none rather than as this one.
func TestTheLoadedFileIsReported(t *testing.T) {
	path := writeBase(t, minimal)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != path {
		t.Errorf("path = %q, want %q", cfg.Path, path)
	}
}

// Every key the loader accepts refuses a value of the wrong type, and names the
// section it was in. A key whose coercion goes unchecked takes whatever TOML
// parsed: a socket path that is a boolean reaches a daemon as an empty string,
// which is a broker listening nowhere reported as a config that loaded.
//
// A boolean is wrong for all of them, whatever each one wants, so one document
// per key asks the question without a table of expected types to keep in step.
func TestEveryKeyRefusesAValueOfTheWrongType(t *testing.T) {
	byName := map[string][]string{
		"server": serverKeys, "keeper": keeperKeys, "executor": executorKeys,
		keyCommand: commandKeys, "ssh": sshKeys, "sudo": sudoKeys,
		"secret": secretKeys, "audit": auditKeys,
	}
	checked := 0
	for _, section := range sections {
		keys := byName[section]
		if len(keys) == 0 {
			t.Errorf("[%s] is a section the loader accepts and this test has no keys for",
				section)
			continue
		}
		for _, key := range keys {
			// minimal already carries [command], and a second header for it is a
			// TOML error rather than the refusal being asked about.
			doc := "[" + section + "]\n" + key + " = true\n"
			if section != keyCommand {
				doc = minimal + "\n" + doc
			}
			checked++
			_, err := load(t, doc)
			if err == nil {
				t.Errorf("[%s] %s accepted a boolean", section, key)
				continue
			}
			// The refusal has to say what was wrong and where: an operator reads it
			// beside a file with one line changed.
			if !strings.Contains(err.Error(), "expected") {
				t.Errorf("[%s] %s was refused without saying what was wanted: %v",
					section, key, err)
			}
			if !strings.Contains(err.Error(), "["+section+"]") {
				t.Errorf("[%s] %s was refused without naming the section: %v",
					section, key, err)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no key was put to the loader, so this asserts nothing")
	}
}
