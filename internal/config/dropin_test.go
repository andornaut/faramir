package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write lays out a base config and any drop-ins beside it, and loads the result
// the way a daemon does.
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

// Settings belonging to a consumer are named without editing the broker's own
// config.
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
	// Accumulated, not replaced.
	if got := cfg.Secrets.Files; len(got) != 2 {
		t.Errorf("files = %v, want the base's and the drop-in's", got)
	}
	// The table around it merged: naming one file keeps the thresholds.
	if cfg.Secrets.MinLength != 12 {
		t.Errorf("min_length = %d, want 12 carried over from the base", cfg.Secrets.MinLength)
	}
	if len(cfg.Sources) != 2 {
		t.Errorf("sources = %v, want the base and one drop-in", cfg.Sources)
	}
}

// Under replace semantics the loser's values would be neither injectable nor
// redacted, silently.
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
		// [ssh] keys is deliberately absent from this table: it is policy rather
		// than an inventory, and TestAPolicyListSetTwiceIsRefused covers it.
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

// Accumulating a policy list would widen what the sockets admit; taking the
// last would make it depend on filename order.
func TestAPolicyListSetTwiceIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, base, dropIn string }{
		{"base and drop-in", "[server]\nallowed_groups = [\"dev\"]\n", "[server]\nallowed_groups = [\"wheel\"]\n"},
		{"decrypt_command", "[secrets]\ndecrypt_command = [\"sops\"]\n", "[secrets]\ndecrypt_command = [\"cat\"]\n"},
		// init mints the key, holds both halves and renders the path, so the
		// list has one owner.  A second identity reaching the same hosts is one
		// no account can vouch for, and the way to use a key of your own is
		// `faramir init --ssh-key`, which adopts it and asserts its mode.
		{"ssh keys", "[ssh]\nkeys = [\"/var/lib/faramir-broker/.ssh/a\"]\n",
			"[ssh]\nkeys = [\"/home/op/.ssh/id_ed25519\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := write(t, minimal+tc.base, map[string]string{"10-x.toml": tc.dropIn})
			if err == nil {
				t.Fatal("a policy list was overridden silently")
			}
			// Both files, since the fix is to remove one.
			if !strings.Contains(err.Error(), "10-x.toml") || !strings.Contains(err.Error(), "config.toml") {
				t.Errorf("error names too little to act on: %v", err)
			}
		})
	}
}

// The section the policy list sits in need not exist in the base file.  A
// drop-in that introduces one owns everything it put there, so a later drop-in
// setting a list inside it is refused like any other second owner -- rather
// than looking unset and overwriting it silently.
func TestAPolicyListInASectionADropInIntroducedIsStillOwned(t *testing.T) {
	_, err := write(t, `
[exec]
default_timeout_sec = 600
`, map[string]string{
		"10-first.toml":  "[secrets]\ndecrypt_command = [\"sops\"]\n",
		"20-second.toml": "[secrets]\ndecrypt_command = [\"cat\"]\n",
	})
	if err == nil {
		t.Fatal("a policy list in a drop-in-introduced section was overridden silently")
	}
	if !strings.Contains(err.Error(), "10-first.toml") || !strings.Contains(err.Error(), "20-second.toml") {
		t.Errorf("error names too little to act on: %v", err)
	}
}

// The .socket units decide what a socket is, so a drop-in setting one of these
// moves nothing -- and does not fail silently either, because the broker dials
// the keeper and the executor at the configured path while systemd keeps
// listening on the old one. That surfaces as "keeper unreachable", which reads
// as an outage rather than an edit.
func TestADropInMayNotSetASocketTheUnitOwns(t *testing.T) {
	for _, key := range []string{"socket_path = \"/run/x.sock\"", "socket_mode = \"0666\""} {
		for _, section := range []string{"server", "keeper", "executor"} {
			t.Run(section+" "+key, func(t *testing.T) {
				_, err := write(t, minimal, map[string]string{
					"10-x.toml": "[" + section + "]\n" + key + "\n",
				})
				if err == nil {
					t.Fatal("a drop-in set a socket the unit owns")
				}
				// Both the file to edit and what to run instead.
				if !strings.Contains(err.Error(), "10-x.toml") ||
					!strings.Contains(err.Error(), "faramir init") {
					t.Errorf("error names too little to act on: %v", err)
				}
			})
		}
	}
}

// The base file is init's to write, and carries every one of them. Refusing
// them there would refuse the config init just rendered.
func TestTheBaseFileMaySetTheSocketsItRenders(t *testing.T) {
	cfg, err := write(t, `
[server]
socket_path = "/run/faramir/broker.sock"
socket_mode = "0660"
[keeper]
socket_path = "/run/faramir/keeper.sock"
[executor]
socket_path = "/run/faramir/exec.sock"
`, map[string]string{"10-x.toml": "[secrets]\nmin_length = 12\n"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Keeper.SocketPath != "/run/faramir/keeper.sock" {
		t.Errorf("keeper socket_path = %q", cfg.Keeper.SocketPath)
	}
	if cfg.Secrets.MinLength != 12 {
		t.Errorf("the drop-in beside it did not apply: min_length = %d", cfg.Secrets.MinLength)
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

// Merged key by key, so a consumer adds one variable without restating PATH.
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
// file is, and every refusal names the drop-in.
func TestADropInIsHeldToTheSameChecks(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown key", "[secrets]\nfile = []\n", "unknown key"},
		{"unknown section", "[secret]\nfiles = []\n", "unknown section"},
		{"out of range", "[server]\nmax_concurrency = 0\n", "max_concurrency"},
		// Refused rather than skipped.
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

// Only .toml, so a backup or .dist beside one is not configuration.
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
