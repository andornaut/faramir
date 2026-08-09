package config

import (
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
[exec]
default_timeout_sec = 600
`

func TestMinimalConfigLoads(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	// Defaults the file did not set.
	if cfg.Server.SocketMode != 0o660 {
		t.Errorf("socket_mode = %o", cfg.Server.SocketMode)
	}
	if cfg.Exec.MaxTimeoutSec != 3600 {
		t.Errorf("max_timeout_sec = %d", cfg.Exec.MaxTimeoutSec)
	}
}

// The key is gone, not optional, so a config still setting it is refused by
// name rather than silently ignored.
func TestDefaultCwdIsRefusedAsUnknown(t *testing.T) {
	_, err := load(t, "[exec]\ndefault_cwd = \"/t\"\n")
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "default_cwd") {
		t.Errorf("the message does not name the key: %v", err)
	}
}

// Same again for the numeric spelling of a caller: allowed_uids said what
// allowed_groups says, in a form that stopped being true once an account was
// renumbered.
func TestAllowedUIDsIsRefusedAsUnknown(t *testing.T) {
	_, err := load(t, minimal+"\n[server]\nallowed_uids = [1000]\n")
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "allowed_groups") {
		t.Errorf("the message does not name the alternative: %v", err)
	}
}

// The executor's own cap is gone, the broker holding a [server] max_concurrency
// slot for the whole of each child and being the only client this socket
// admits: a number four times above a ceiling that always binds first.
func TestExecutorMaxConcurrencyIsRefusedAsUnknown(t *testing.T) {
	_, err := load(t, minimal+"\n[executor]\nmax_concurrency = 8\n")
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("err = %v", err)
	}
}

// The broker no longer grades a secret's strength, so the two keys that did are
// refused rather than quietly ignored: a config still setting one is asking for
// a check that is not made, and reading as though it were.
func TestTheStrengthThresholdsAreRefusedAsUnknown(t *testing.T) {
	for _, key := range []string{"min_unique_chars = 4", "min_entropy_bits_per_char = 1.5"} {
		t.Run(key, func(t *testing.T) {
			_, err := load(t, minimal+"\n[secrets]\n"+key+"\n")
			if err == nil || !strings.Contains(err.Error(), "unknown key") {
				t.Fatalf("err = %v", err)
			}
			if !strings.Contains(err.Error(), "min_length") {
				t.Errorf("the message does not name what is left: %v", err)
			}
		})
	}
}

// A mistyped key is named, not ignored.
func TestUnknownKeysAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"a misspelling in [server]", minimal + "\n[server]\nsoket_path = \"/x\"\n"},
		{"a singular where the key is plural", "[exec]\nterm_col = 80\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.text)
			if err == nil || !strings.Contains(err.Error(), "unknown key") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// [secret] for [secrets] leaves a broker managing no files while reading as
// though it were configured.
func TestUnknownSectionsAreRefused(t *testing.T) {
	_, err := load(t, minimal+"\n[secret]\nfiles = [\"/x.sops.yml\"]\n")
	if err == nil {
		t.Fatal("a mistyped section was accepted")
	}
	for _, want := range []string{"unknown section", "secret", "secrets"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %v", want, err)
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
		{"zero default_timeout_sec", "[exec]\ndefault_timeout_sec = 0\n"},
		{"zero max_timeout_sec", "[exec]\nmax_timeout_sec = 0\n"},
		{"zero max_output_bytes", "[exec]\nmax_output_bytes = 0\n"},
		{"negative kill_grace_sec", "[exec]\nkill_grace_sec = -1\n"},
		{"term_cols past a uint16", "[exec]\nterm_cols = 70000\n"},
		{"zero term_rows", "[exec]\nterm_rows = 0\n"},
		{"negative refresh", minimal + "\n[secrets]\nrefresh_interval_sec = -1\n"},
		{"zero min_length", minimal + "\n[secrets]\nmin_length = 0\n"},
		{"negative max_record_bytes", minimal + "\n[audit]\nmax_record_bytes = -1\n"},
		// A malformed pattern matches nothing, reading as a missing store.
		{"unclosed character class", minimal + "\n[secrets]\nfiles = [\"/s/[a-.sops.yml\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(t, tc.text); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// A max below the default replaces it for every command rather than capping
// it.
func TestMaxTimeoutBelowDefaultIsRefused(t *testing.T) {
	_, err := load(t, "[exec]\ndefault_timeout_sec = 600\nmax_timeout_sec = 60\n")
	if err == nil || !strings.Contains(err.Error(), "max_timeout_sec") {
		t.Fatalf("err = %v", err)
	}
}

// The meaningful zeroes stay legal.
func TestMeaningfulZeroesAreAccepted(t *testing.T) {
	cfg, err := load(t, "[exec]\nkill_grace_sec = 0\n"+
		"[secrets]\nrefresh_interval_sec = 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Exec.KillGraceSec != 0 || cfg.Secrets.RefreshIntervalSec != 0 {
		t.Errorf("kill_grace_sec = %d, refresh_interval_sec = %d",
			cfg.Exec.KillGraceSec, cfg.Secrets.RefreshIntervalSec)
	}
}

func TestOctalModeSpellings(t *testing.T) {
	for _, spelling := range []string{`"0660"`, `0o660`} {
		cfg, err := load(t, minimal+"\n[server]\nsocket_mode = "+spelling+"\n")
		if err != nil {
			t.Fatalf("%s: %v", spelling, err)
		}
		if cfg.Server.SocketMode != 0o660 {
			t.Errorf("%s -> %o, want 660", spelling, cfg.Server.SocketMode)
		}
	}
	// An unquoted decimal 660 means 0o1224.
	_, err := load(t, minimal+"\n[server]\nsocket_mode = 660\n")
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("decimal 660 was accepted: %v", err)
	}
}

func TestScalarWhereTableExpected(t *testing.T) {
	_, err := load(t, "server = \"0660\"\n"+minimal)
	if err == nil || !strings.Contains(err.Error(), "expected a [server] table") {
		t.Fatalf("err = %v", err)
	}
}

func TestDecryptCommandDefaultsAndOverrides(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	want := "sops --output-type json --decrypt {file}"
	if strings.Join(cfg.Secrets.DecryptCommand, " ") != want {
		t.Errorf("default decrypt_command = %v", cfg.Secrets.DecryptCommand)
	}

	cfg, err = load(t, minimal+"\n[secrets]\ndecrypt_command = [\"/opt/sops\", \"-d\", \"{file}\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secrets.DecryptCommand[0] != "/opt/sops" {
		t.Errorf("override ignored: %v", cfg.Secrets.DecryptCommand)
	}
}
