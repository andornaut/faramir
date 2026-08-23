package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The config is one file faramir owns, read at startup by three daemons. A file
// that is wrong is refused with a reason, and never half-applied: a Config that
// comes back has to be one the daemons can act on.
func FuzzLoadRefusesRatherThanHalfApplying(f *testing.F) {
	f.Add("[server]\nsocket_path = \"/run/faramir/broker.sock\"\n")
	f.Add("[secret]\nmin_length = 0\n")
	f.Add("[command]\ntimeout_sec = -1\n")
	f.Add("nonsense")

	f.Fuzz(func(t *testing.T, body string) {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Skip()
		}
		cfg, err := Load(path)
		if err != nil {
			if cfg != nil {
				t.Fatalf("a refused config came back with a value: %+v", cfg)
			}
			return
		}
		if cfg == nil {
			t.Fatal("Load returned no config and no error")
		}
		if cfg.Secret.MinLength < 1 {
			t.Fatalf("accepted min_length = %d", cfg.Secret.MinLength)
		}
		if cfg.Command.TimeoutSec < 1 || cfg.Command.MaxTimeoutSec < 1 {
			t.Fatalf("accepted timeout_sec = %d, max_timeout_sec = %d",
				cfg.Command.TimeoutSec, cfg.Command.MaxTimeoutSec)
		}
		if cfg.Command.TimeoutSec > cfg.Command.MaxTimeoutSec {
			t.Fatalf("accepted a default timeout above the maximum: %d > %d",
				cfg.Command.TimeoutSec, cfg.Command.MaxTimeoutSec)
		}
	})
}
