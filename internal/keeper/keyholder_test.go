package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sopstest"
)

// scrub works from the identity format, so it needs no copy of the key.
func TestScrubRemovesKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := sopstest.NewIdentity(t, dir)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var identity string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "AGE-SECRET-KEY") {
			identity = line
		}
	}
	if identity == "" {
		t.Fatal("no identity in the fixture")
	}

	keys := newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
	scrubbed := keys.scrub("sops said: " + identity + " <- oops")
	if strings.Contains(scrubbed, "AGE-SECRET-KEY") {
		t.Errorf("key material survived scrub: %q", scrubbed)
	}
	if !strings.Contains(scrubbed, "«AGE-KEY»") {
		t.Errorf("no replacement token: %q", scrubbed)
	}
}

// Where the age key is found, and in which order. systemd hands the keeper its
// key as a credential, so that is preferred over a path in the config: the
// credential is a file the keeper's own uid can open under a directory systemd
// made for it, and the configured path may be one it cannot reach at all.
//
// The empty AgeKeyCredential case is the one the conjunction is for. os.Open
// succeeds on a directory, so joining CREDENTIALS_DIRECTORY with "" and opening
// the result hands sops the credentials directory as though it were the key.
func TestTheKeyIsTakenFromTheCredentialBeforeTheConfiguredPath(t *testing.T) {
	// Two real files, so a case that picks the wrong one still gets a readable
	// path back and the assertion is about which, not about whether.
	credsDir := t.TempDir()
	credential := filepath.Join(credsDir, "age_key")
	if err := os.WriteFile(credential, []byte("# not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configured := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(configured, []byte("# not a key either\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		credsDir   string
		credential string
		keyFile    string
		want       string
		why        string
	}{
		{"the credential wins", credsDir, "age_key", configured, credential,
			"systemd put it there for this uid"},
		{"and is enough on its own", credsDir, "age_key", "", credential, ""},
		{"a credential that is not there falls back", credsDir, "absent", configured, configured,
			"a name that resolves to nothing is not an answer"},
		{"no credentials directory", "", "age_key", configured, configured,
			"nothing ran this under systemd"},
		{"a directory is offered but no credential is named", credsDir, "", configured, configured,
			"or the credentials directory itself is handed to sops as the key"},
		{"nothing anywhere", "", "", "", "", "reported as none rather than as a path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CREDENTIALS_DIRECTORY", tc.credsDir)
			k := newKeyHolder(config.KeeperConfig{
				AgeKeyCredential: tc.credential, AgeKeyFile: tc.keyFile,
			})
			if got := k.Path(); got != tc.want {
				t.Errorf("Path() = %q, want %q: %s", got, tc.want, tc.why)
			}
		})
	}
}

// Looked up once and remembered: the path is asked for on every decryption, and
// a keeper that re-stats the credential each time reports a key that went away
// as a key it never had.
func TestTheKeyPathIsResolvedOnce(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "age.key")
	if err := os.WriteFile(keyFile, []byte("# not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	k := newKeyHolder(config.KeeperConfig{AgeKeyFile: keyFile})
	first := k.Path()
	if first != keyFile {
		t.Fatalf("Path() = %q, want %q", first, keyFile)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if second := k.Path(); second != first {
		t.Errorf("Path() = %q after the file went away, want the %q it already resolved",
			second, first)
	}
}
