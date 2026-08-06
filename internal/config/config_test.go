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
	return FromMap(raw, "<test>")
}

const minimal = `
[exec]
default_cwd = "/home/agent/work/repo"
`

func TestMinimalConfigLoads(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Exec.DefaultCwd != "/home/agent/work/repo" {
		t.Errorf("default_cwd = %q", cfg.Exec.DefaultCwd)
	}
	// Defaults the file did not set.
	if cfg.Server.SocketMode != 0o660 {
		t.Errorf("socket_mode = %o", cfg.Server.SocketMode)
	}
	if cfg.Exec.MaxTimeoutSec != 3600 {
		t.Errorf("max_timeout_sec = %d", cfg.Exec.MaxTimeoutSec)
	}
}

func TestDefaultCwdIsRequired(t *testing.T) {
	_, err := load(t, "[server]\nmax_concurrency = 2\n")
	if err == nil || !strings.Contains(err.Error(), "default_cwd is required") {
		t.Fatalf("err = %v", err)
	}
}

// A mistyped key must be named, not ignored: silently dropping it leaves the
// setting at a default the operator thought they had changed.
func TestUnknownKeysAreRefused(t *testing.T) {
	cases := map[string]string{
		"server": minimal + "\n[server]\nsoket_path = \"/x\"\n",
		"exec":   "[exec]\ndefault_cwd = \"/t\"\nterm_col = 80\n",
	}
	for name, text := range cases {
		_, err := load(t, text)
		if err == nil || !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// A mistyped section is as silent as a mistyped key and worse in its effect:
// [secret] for [secrets] leaves a broker that manages no files and therefore
// redacts nothing, while reading as though it were configured.
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

// Checking key names but not their values leaves the same failure this file
// exists to prevent.  Each of these has a concrete consequence, named in the
// loader: a broker that panics on startup, refuses every request as busy, or
// kills every command the instant it starts.
func TestOutOfRangeValuesAreRefused(t *testing.T) {
	cases := map[string]string{
		"negative max_concurrency":  minimal + "\n[server]\nmax_concurrency = -1\n",
		"zero max_concurrency":      minimal + "\n[server]\nmax_concurrency = 0\n",
		"zero executor concurrency": minimal + "\n[executor]\nmax_concurrency = 0\n",
		"zero max_request_bytes":    minimal + "\n[server]\nmax_request_bytes = 0\n",
		"zero default_timeout_sec":  "[exec]\ndefault_cwd = \"/t\"\ndefault_timeout_sec = 0\n",
		"zero max_timeout_sec":      "[exec]\ndefault_cwd = \"/t\"\nmax_timeout_sec = 0\n",
		"zero max_output_bytes":     "[exec]\ndefault_cwd = \"/t\"\nmax_output_bytes = 0\n",
		"negative kill_grace_sec":   "[exec]\ndefault_cwd = \"/t\"\nkill_grace_sec = -1\n",
		"term_cols past a uint16":   "[exec]\ndefault_cwd = \"/t\"\nterm_cols = 70000\n",
		"zero term_rows":            "[exec]\ndefault_cwd = \"/t\"\nterm_rows = 0\n",
		"negative refresh":          minimal + "\n[secrets]\nrefresh_interval_sec = -1\n",
		"zero min_length":           minimal + "\n[secrets]\nmin_length = 0\n",
		"zero min_unique_chars":     minimal + "\n[secrets]\nmin_unique_chars = 0\n",
		"negative min_entropy":      minimal + "\n[secrets]\nmin_entropy_bits_per_char = -1.0\n",
		"negative max_record_bytes": minimal + "\n[audit]\nmax_record_bytes = -1\n",
	}
	for name, text := range cases {
		if _, err := load(t, text); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A max below the default does not cap it, it replaces it for every command,
// which makes default_timeout_sec a setting that reads as though it applies.
func TestMaxTimeoutBelowDefaultIsRefused(t *testing.T) {
	_, err := load(t, "[exec]\ndefault_cwd = \"/t\"\ndefault_timeout_sec = 600\nmax_timeout_sec = 60\n")
	if err == nil || !strings.Contains(err.Error(), "max_timeout_sec") {
		t.Fatalf("err = %v", err)
	}
}

// The meaningful zeroes stay legal: kill_grace_sec 0 is "SIGKILL at once", and
// refresh_interval_sec 0 is "check on every request".
func TestMeaningfulZeroesAreAccepted(t *testing.T) {
	cfg, err := load(t, "[exec]\ndefault_cwd = \"/t\"\nkill_grace_sec = 0\n"+
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
	// An unquoted decimal 660 means 0o1224, which is out of range and a
	// plausible typo for 0o660.
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

func TestAgeKeyMovedToKeeper(t *testing.T) {
	_, err := load(t, minimal+"\n[secrets]\nage_key_file = \"/etc/faramir/age.key\"\n")
	if err == nil || !strings.Contains(err.Error(), "moved to [keeper]") {
		t.Fatalf("err = %v", err)
	}
}

// --------------------------------------------------------------------------
// The allowlist and sync removals
//
// All three are hard errors, not silently ignored keys.  A config still
// carrying them reads as though commands were being constrained, or as though
// the broker still executed a separate checkout, which is the one way these
// removals could mislead an operator.
// --------------------------------------------------------------------------

func TestALeftoverAllowTableIsAConfigError(t *testing.T) {
	_, err := load(t, minimal+"\n[[allow]]\nname = \"ls\"\nargv0 = \"^ls$\"\n")
	if err == nil || !strings.Contains(err.Error(), "[[allow]]") {
		t.Fatalf("err = %v", err)
	}
}

func TestALeftoverAllowedBinDirsIsAConfigError(t *testing.T) {
	_, err := load(t, "[exec]\ndefault_cwd = \"/t\"\nallowed_bin_dirs = [\"/usr/bin\"]\n")
	if err == nil {
		t.Fatal("allowed_bin_dirs was accepted")
	}
	// The message has to say where a venv goes now, not just that the key died.
	for _, want := range []string{"allowed_bin_dirs", "base_env"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %v", want, err)
		}
	}
}

func TestALeftoverSyncSectionIsAConfigError(t *testing.T) {
	_, err := load(t, minimal+"\n[sync]\nenabled = true\nsource = \"/a\"\ndest = \"/b\"\n")
	if err == nil || !strings.Contains(err.Error(), "[sync] no longer exists") {
		t.Fatalf("err = %v", err)
	}
}

func TestAConfigWithNoneOfThemLoads(t *testing.T) {
	cfg, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Exec.DefaultCwd != "/home/agent/work/repo" {
		t.Errorf("default_cwd = %q", cfg.Exec.DefaultCwd)
	}
}
