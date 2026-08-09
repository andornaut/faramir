package main

import (
	"os"
	"path/filepath"
	"testing"
)

// brokerConfig writes a config whose sockets are in a temp directory, so
// starting a broker against it reaches no installed host.
func brokerConfig(t *testing.T, secretsFiles string) string {
	t.Helper()
	dir := t.TempDir()
	body := `
[server]
socket_path = "` + filepath.Join(dir, "broker.sock") + `"
[keeper]
socket_path = "` + filepath.Join(dir, "keeper.sock") + `"
[executor]
socket_path = "` + filepath.Join(dir, "exec.sock") + `"
[audit]
log_path = "` + filepath.Join(dir, "audit.log") + `"
[secrets]
files = [` + secretsFiles + `]
`
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The gate --check applies, applied where it decides something.
//
// --check runs from init and from doctor, neither of which runs at boot, so a
// store that becomes unloadable after the install used to leave the broker
// bound and serving with a value set that was short or empty. Every unit
// reported itself active and nothing was redacted.
func TestTheBrokerRefusesToStartWhenTheStoreWillNotLoad(t *testing.T) {
	// No keeper is listening on that socket, which is the cold-start case: no
	// previous value set to fall back on, so there is nothing to serve.
	config := brokerConfig(t, `"`+filepath.Join(t.TempDir(), "*.sops.yml")+`"`)
	if code := run([]string{"broker", "-c", config}); code == 0 {
		t.Error("the broker started with a store it could not load")
	}
}

// The config still has to be judged before the store is reached: --parse-only
// is what the installers call before anything is running, so it must not start
// answering "no keeper" to a question about syntax.
func TestParseOnlyDoesNotNeedAStoreThatLoads(t *testing.T) {
	config := brokerConfig(t, `"`+filepath.Join(t.TempDir(), "*.sops.yml")+`"`)
	if code := run([]string{"broker", "-c", config, "--parse-only"}); code != 0 {
		t.Errorf("--parse-only returned %d on a config that parses", code)
	}
}
