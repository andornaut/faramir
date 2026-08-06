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
