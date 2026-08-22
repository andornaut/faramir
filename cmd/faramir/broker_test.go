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
`
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The daemon starts on a store it cannot load and refuses the two ops that
// would be unsafe, which is tested at the server. What has to hold here is
// that --check still fails on it: init and doctor read that exit code, and an
// operator asking is asking to be told.
func TestCheckFailsWhenTheStoreWillNotLoad(t *testing.T) {
	// No keeper is listening on that socket, which is the cold-start case: no
	// previous value set to fall back on, so there is nothing to serve.
	config := brokerConfig(t, `"`+filepath.Join(t.TempDir(), "*.sops.yml")+`"`)
	t.Setenv("FARAMIR_CONFIG", config)
	if code := run([]string{"broker", "--check"}); code == 0 {
		t.Error("--check passed with a secrets directory it could not load")
	}
}

// The config still has to be judged before the secrets directory is reached:
// --parse-only is what the installers call before anything is running, so it
// must not start answering "no keeper" to a question about syntax.
func TestParseOnlyDoesNotNeedAStoreThatLoads(t *testing.T) {
	config := brokerConfig(t, `"`+filepath.Join(t.TempDir(), "*.sops.yml")+`"`)
	t.Setenv("FARAMIR_CONFIG", config)
	if code := run([]string{"broker", "--parse-only"}); code != 0 {
		t.Errorf("--parse-only returned %d on a config that parses", code)
	}
}
