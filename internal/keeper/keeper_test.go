package keeper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sops "github.com/getsops/sops/v3"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sopstest"
)

func fixture(t *testing.T, branch sops.TreeBranch) (config.SecretsConfig, *KeyHolder) {
	t.Helper()
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	secretPath := filepath.Join(dir, "vault.sops.yaml")
	sopstest.WriteEncrypted(t, secretPath, recipient, branch)

	return config.SecretsConfig{
			Files:          []string{secretPath},
			DecryptCommand: sopstest.DecryptCommand(t),
		},
		NewKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
}

func TestDecryptRoundTrip(t *testing.T) {
	secrets, keys := fixture(t, sops.TreeBranch{
		{Key: "router", Value: sops.TreeBranch{
			{Key: "admin", Value: "hunter2hunter2"},
		}},
		{Key: "flat", Value: "s3cr3t-value-here"},
		{Key: "enabled", Value: true},
	})

	values, errs := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if got := values["router/admin"]; got != "hunter2hunter2" {
		t.Errorf("router/admin = %q", got)
	}
	if got := values["flat"]; got != "s3cr3t-value-here" {
		t.Errorf("flat = %q", got)
	}
	// Booleans are never secret, and "true"/"false" would redact half the output.
	if _, ok := values["enabled"]; ok {
		t.Errorf("boolean leaked into the value set: %v", values)
	}
	for ref := range values {
		if ref == "sops" || strings.HasPrefix(ref, "sops/") {
			t.Errorf("sops metadata leaked into the value set: %s", ref)
		}
	}
}

// The key material must reach sops as a path, never as a value.  Setting
// SOPS_AGE_KEY would put the master key in a child's environment block.
func TestKeyMaterialNeverEntersTheEnvironment(t *testing.T) {
	for _, name := range []string{"SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE"} {
		if v, ok := os.LookupEnv(name); ok {
			t.Fatalf("%s is set in the test environment (%q); the test proves nothing", name, v)
		}
	}
	secrets, keys := fixture(t, sops.TreeBranch{
		{Key: "token", Value: "correct-horse-battery"},
	})
	values, errs := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if values["token"] != "correct-horse-battery" {
		t.Errorf("token = %q", values["token"])
	}

	// The keeper must not have read the key: only its path.
	raw, err := os.ReadFile(keys.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "AGE-SECRET-KEY") {
		t.Fatalf("fixture is not an age identity: %q", raw)
	}
}

// A wrong identity must fail loudly, not return an empty value set: an empty
// set means nothing is redacted.
func TestWrongIdentityFails(t *testing.T) {
	secrets, _ := fixture(t, sops.TreeBranch{{Key: "token", Value: "value-goes-here"}})

	other := t.TempDir()
	wrongKey, _ := sopstest.NewIdentity(t, other)
	keys := NewKeyHolder(config.KeeperConfig{AgeKeyFile: wrongKey})

	values, errs := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Fatal("decrypting with the wrong identity reported no error")
	}
	if len(values) != 0 {
		t.Errorf("values were returned anyway: %v", values)
	}
}

// One broken file must not blank the whole value set.
func TestOneBadFileDoesNotBlankTheSet(t *testing.T) {
	secrets, keys := fixture(t, sops.TreeBranch{{Key: "good", Value: "a-good-value-x"}})
	broken := filepath.Join(t.TempDir(), "broken.sops.yaml")
	if err := os.WriteFile(broken, []byte("not: sops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets.Files = append(secrets.Files, broken)

	values, errs := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Error("the broken file produced no error")
	}
	if values["good"] != "a-good-value-x" {
		t.Errorf("the good file was lost: %v", values)
	}
}

// The keeper serves get_values and nothing else.  Verification matrix test 1f.
func TestKeeperRefusesEveryOtherOp(t *testing.T) {
	k := &Keeper{config: &config.Config{}, Keys: NewKeyHolder(config.KeeperConfig{})}
	for _, op := range []string{"get_age_key", "get_key", "", "decrypt", "exec"} {
		resp := k.Handle(map[string]any{"op": op})
		errObj, ok := resp["error"].(map[string]string)
		if !ok {
			t.Fatalf("op %q was not refused: %v", op, resp)
		}
		if errObj["code"] != "unsupported" {
			t.Errorf("op %q: code = %q, want unsupported", op, errObj["code"])
		}
		if _, leaked := resp["values"]; leaked {
			t.Errorf("op %q returned values", op)
		}
	}
}

// Scrub works from the identity format, so it needs no copy of the key.
func TestScrubRemovesKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := sopstest.NewIdentity(t, dir)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var identity string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "AGE-SECRET-KEY") {
			identity = line
		}
	}
	if identity == "" {
		t.Fatal("no identity in the fixture")
	}

	keys := NewKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
	scrubbed := keys.Scrub("sops said: " + identity + " <- oops")
	if strings.Contains(scrubbed, "AGE-SECRET-KEY") {
		t.Errorf("key material survived Scrub: %q", scrubbed)
	}
	if !strings.Contains(scrubbed, "«AGE-KEY»") {
		t.Errorf("no replacement token: %q", scrubbed)
	}
}

func TestFlattenSkipsSopsMetadataAndBooleans(t *testing.T) {
	var tree any
	if err := json.Unmarshal([]byte(`{
		"sops": {"mac": "deadbeef"},
		"sops_backup_token": "keep-me-please",
		"a": {"b": ["x", "y"]},
		"flag": true,
		"nothing": null,
		"n": 42
	}`), &tree); err != nil {
		t.Fatal(err)
	}
	got := Flatten(tree)

	want := map[string]string{
		"sops_backup_token": "keep-me-please",
		"a/b/0":             "x",
		"a/b/1":             "y",
		"n":                 "42",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, absent := range []string{"sops/mac", "sops", "flag", "nothing"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s should not be a secret ref", absent)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected refs: %v", got)
	}
}
