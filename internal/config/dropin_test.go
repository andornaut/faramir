package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write lays out a base config and any drop-ins, and loads the result the way
// a daemon does.  The drop-in directory sits beside the base file, so the whole
// arrangement moves with the config path rather than being pinned to /etc.
func write(t *testing.T, base string, dropIns map[string]string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if dropIns != nil {
		dropInDir := filepath.Join(dir, dropInDirName)
		if err := os.Mkdir(dropInDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range dropIns {
			if err := os.WriteFile(filepath.Join(dropInDir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return Load(path)
}

func TestABaseConfigWithNoDropInDirectoryLoads(t *testing.T) {
	cfg, err := write(t, minimal, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 1 {
		t.Errorf("sources = %v, want the base alone", cfg.Sources)
	}
}

// The point of the feature: the settings that belong to whatever consumes the
// broker are named somewhere the broker's own config is not edited.
func TestADropInReplacesAListAndIsRecorded(t *testing.T) {
	cfg, err := write(t, minimal+`
[secrets]
files = ["/etc/faramir/secrets/base.sops.yml"]
min_length = 12
`, map[string]string{
		"10-consumer.toml": `
[secrets]
files = ["/etc/faramir/secrets/consumer.sops.yml"]
`})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Secrets.Files; len(got) != 1 || !strings.HasSuffix(got[0], "consumer.sops.yml") {
		t.Errorf("files = %v, want the drop-in's list alone", got)
	}
	// Replaced the list, merged the table: a drop-in naming one file must not
	// silently drop the thresholds beside it.
	if cfg.Secrets.MinLength != 12 {
		t.Errorf("min_length = %d, want 12 carried over from the base", cfg.Secrets.MinLength)
	}
	if len(cfg.Sources) != 2 {
		t.Errorf("sources = %v, want the base and one drop-in", cfg.Sources)
	}
}

// Lexical order, so a numeric prefix decides who wins.
func TestTheLastDropInWins(t *testing.T) {
	cfg, err := write(t, minimal, map[string]string{
		"10-first.toml":  "[audit]\nlog_path = \"/tmp/first.log\"\n",
		"20-second.toml": "[audit]\nlog_path = \"/tmp/second.log\"\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.LogPath != "/tmp/second.log" {
		t.Errorf("log_path = %q, want the later drop-in's", cfg.Audit.LogPath)
	}
}

// base_env is a table of arbitrary names, so merging it key by key is what lets
// a consumer add one variable without restating PATH.
func TestADropInAddsToBaseEnvWithoutRestatingIt(t *testing.T) {
	cfg, err := write(t, `
[exec]
default_timeout_sec = 600
[exec.base_env]
PATH = "/usr/bin"
`, map[string]string{
		"10-consumer.toml": "[exec.base_env]\nANSIBLE_NOCOWS = \"1\"\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Exec.BaseEnv["PATH"] != "/usr/bin" {
		t.Errorf("PATH = %q, want the base's", cfg.Exec.BaseEnv["PATH"])
	}
	if cfg.Exec.BaseEnv["ANSIBLE_NOCOWS"] != "1" {
		t.Errorf("the drop-in's variable is missing: %v", cfg.Exec.BaseEnv)
	}
}

// Validation runs after merging, so a drop-in is held to every rule the base
// file is.  Checking before would let a drop-in write what the base could not.
func TestADropInIsHeldToTheSameChecks(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown key", "[secrets]\nfile = []\n", "unknown key"},
		{"unknown section", "[secret]\nfiles = []\n", "unknown section"},
		{"out of range", "[server]\nmax_concurrency = 0\n", "max_concurrency"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := write(t, minimal, map[string]string{"10-bad.toml": tc.body})
			if err == nil {
				t.Fatal("the drop-in was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// Named in the error, because "which file said that" is the first question and
// the base file is the wrong answer when a drop-in is what set it.
func TestAnErrorNamesEveryFileThatContributed(t *testing.T) {
	_, err := write(t, minimal, map[string]string{"10-bad.toml": "[secrets]\nfile = []\n"})
	if err == nil {
		t.Fatal("the drop-in was accepted")
	}
	if !strings.Contains(err.Error(), "10-bad.toml") {
		t.Errorf("error does not name the drop-in: %v", err)
	}
}

// A file that does not parse is refused rather than skipped.  A drop-in that
// should have applied and did not is a broker managing fewer files than its
// operator believes.
func TestADropInThatDoesNotParseIsRefused(t *testing.T) {
	_, err := write(t, minimal, map[string]string{"10-bad.toml": "this is not toml\n"})
	if err == nil {
		t.Fatal("a malformed drop-in was ignored")
	}
	if !strings.Contains(err.Error(), "10-bad.toml") {
		t.Errorf("error does not name the drop-in: %v", err)
	}
}

// Only .toml, so an editor backup or a .dist left beside one does not silently
// become configuration.
func TestOnlyTomlFilesAreRead(t *testing.T) {
	cfg, err := write(t, minimal, map[string]string{
		"10-real.toml":      "[audit]\nlog_path = \"/tmp/real.log\"\n",
		"20-backup.toml.sw": "[audit]\nlog_path = \"/tmp/swap.log\"\n",
		"30-old.toml.dist":  "[audit]\nlog_path = \"/tmp/dist.log\"\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.LogPath != "/tmp/real.log" {
		t.Errorf("log_path = %q, want only the .toml applied", cfg.Audit.LogPath)
	}
	if len(cfg.Sources) != 2 {
		t.Errorf("sources = %v, want the base and the one .toml", cfg.Sources)
	}
}
