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
func TestADropInAddsToTheInventoryAndIsRecorded(t *testing.T) {
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
	// Accumulated, not replaced: both are files somebody asked to have managed.
	if got := cfg.Secrets.Files; len(got) != 2 {
		t.Errorf("files = %v, want the base's and the drop-in's", got)
	}
	// Merged the table around it: naming one file must not drop the thresholds.
	if cfg.Secrets.MinLength != 12 {
		t.Errorf("min_length = %d, want 12 carried over from the base", cfg.Secrets.MinLength)
	}
	if len(cfg.Sources) != 2 {
		t.Errorf("sources = %v, want the base and one drop-in", cfg.Sources)
	}
}

// Lists accumulate rather than replace, which is the failure this rule exists
// for: under replace semantics the loser's values are neither injectable nor in
// the redaction set, with nothing said about it.
func TestListsAccumulateAcrossDropIns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dropIns map[string]string
		get     func(*Config) []string
		want    int
		why     string
	}{
		{name: "two projects, two stores",
			dropIns: map[string]string{
				"ansible-ctrl.toml": "[secrets]\nfiles = [\"/etc/faramir/secrets/ansible-ctrl.sops.yml\"]\n",
				"webapp.toml":       "[secrets]\nfiles = [\"/etc/faramir/secrets/webapp.sops.yml\"]\n",
			},
			get: func(c *Config) []string { return c.Secrets.Files }, want: 2,
			why: "both projects have to end up managed"},
		{name: "two consumers, two keys, one agent",
			dropIns: map[string]string{
				"10-a.toml": "[ssh]\nkeys = [\"/var/lib/faramir-broker/.ssh/a\"]\n",
				"20-b.toml": "[ssh]\nkeys = [\"/var/lib/faramir-broker/.ssh/b\"]\n",
			},
			get: func(c *Config) []string { return c.Ssh.Keys }, want: 2},
		{name: "the same store named twice",
			dropIns: map[string]string{
				"10-a.toml": "[secrets]\nfiles = [\"/etc/faramir/secrets/shared.sops.yml\"]\n",
				"20-b.toml": "[secrets]\nfiles = [\"/etc/faramir/secrets/shared.sops.yml\"]\n",
			},
			get: func(c *Config) []string { return c.Secrets.Files }, want: 1,
			why: "named twice is managed once, so a shared store is not decrypted or reported twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := write(t, minimal, tc.dropIns)
			if err != nil {
				t.Fatal(err)
			}
			if got := tc.get(cfg); len(got) != tc.want {
				t.Errorf("got %v, want %d entries: %s", got, tc.want, tc.why)
			}
		})
	}
}

// Policy lists are refused rather than accumulated or silently replaced.
// Accumulating would widen what the sockets admit by writing a file that never
// said so; taking the last would make it depend on filename order.
func TestAPolicyListSetTwiceIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, base, dropIn string }{
		{"base and drop-in", "[server]\nallowed_groups = [\"dev\"]\n", "[server]\nallowed_groups = [\"wheel\"]\n"},
		{"decrypt_command", "[secrets]\ndecrypt_command = [\"sops\"]\n", "[secrets]\ndecrypt_command = [\"cat\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := write(t, minimal+tc.base, map[string]string{"10-x.toml": tc.dropIn})
			if err == nil {
				t.Fatal("a policy list was overridden silently")
			}
			// Both files, because the fix is to remove it from one of them.
			if !strings.Contains(err.Error(), "10-x.toml") || !strings.Contains(err.Error(), "config.toml") {
				t.Errorf("error names too little to act on: %v", err)
			}
		})
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
//
// Every refusal names the drop-in, asserted on each row rather than in a test
// of its own: "which file said that" is the first question, and the base file
// is the wrong answer when a drop-in is what set it.
func TestADropInIsHeldToTheSameChecks(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown key", "[secrets]\nfile = []\n", "unknown key"},
		{"unknown section", "[secret]\nfiles = []\n", "unknown section"},
		{"out of range", "[server]\nmax_concurrency = 0\n", "max_concurrency"},
		// Refused rather than skipped: a drop-in that should have applied and
		// did not is a broker managing fewer files than its operator believes.
		{"not toml at all", "this is not toml\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := write(t, minimal, map[string]string{"10-bad.toml": tc.body})
			if err == nil {
				t.Fatal("the drop-in was accepted")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "10-bad.toml") {
				t.Errorf("error does not name the drop-in: %v", err)
			}
		})
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
