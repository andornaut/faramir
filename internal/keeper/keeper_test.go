package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sopstest"
	"github.com/andornaut/faramir/internal/version"
)

// states, errorsIn and unresolved are one field of a keeper response at the
// type it is documented to carry. Checked rather than asserted: a response of
// another shape is a failure of the op under test, and a panic mid-test says
// less about it than a message naming what came back.
func states(t *testing.T, resp map[string]any) []FileState {
	t.Helper()
	value, ok := resp["state"].([]FileState)
	if !ok {
		t.Fatalf("state = %#v, want []FileState", resp["state"])
	}
	return value
}

func errorsIn(t *testing.T, resp map[string]any) []string {
	t.Helper()
	value, ok := resp["errors"].([]string)
	if !ok {
		t.Fatalf("errors = %#v, want []string", resp["errors"])
	}
	return value
}

func unresolved(t *testing.T, resp map[string]any) []string {
	t.Helper()
	value, ok := resp["unresolved_patterns"].([]string)
	if !ok {
		t.Fatalf("unresolved_patterns = %#v, want []string", resp["unresolved_patterns"])
	}
	return value
}

func fixture(t *testing.T, branch sopstest.Branch) (config.SecretConfig, *KeyHolder) {
	t.Helper()
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	secretPath := filepath.Join(dir, "vault.sops.yaml")
	sopstest.WriteEncrypted(t, secretPath, recipient, branch)

	return config.SecretConfig{
			Patterns:       []string{secretPath},
			DecryptCommand: sopstest.DecryptCommand(t),
		},
		newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
}

// handle is Keeper.Handle with the version the broker sends filled in, the
// keeper refusing a request that names another. What the gate itself does is
// TestARequestOfAnotherReleaseIsRefused.
func handle(k *Keeper, request map[string]any) map[string]any {
	if request != nil {
		if _, ok := request["version"]; !ok {
			request["version"] = version.Version
		}
	}
	return k.Handle(request)
}

// get_values and get_state, and nothing else.
func TestKeeperRefusesEveryOtherOp(t *testing.T) {
	k := &Keeper{config: &config.Config{}, Keys: newKeyHolder(config.KeeperConfig{})}
	for _, op := range []string{"get_age_key", "get_key", "", "decrypt", "exec"} {
		resp := handle(k, map[string]any{"op": op})
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

// The poll answers without the key and without execing sops, so a keeper that
// cannot decrypt still reports edits.
func TestGetStateFingerprintsWithoutDecrypting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.sops.yaml")
	if err := os.WriteFile(path, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &Keeper{
		config: &config.Config{Secret: config.SecretConfig{
			Patterns:       []string{path},
			DecryptCommand: []string{"/nonexistent/sops", "{file}"},
		}},
		Keys: newKeyHolder(config.KeeperConfig{}),
	}

	resp := handle(k, map[string]any{"op": "get_state"})
	if _, leaked := resp["values"]; leaked {
		t.Error("get_state returned values")
	}
	state, ok := resp["state"].([]FileState)
	if !ok || len(state) != 1 {
		t.Fatalf("state = %v", resp["state"])
	}
	if state[0].Path != path || state[0].Size != int64(len("ciphertext")) || state[0].MTime == 0 {
		t.Errorf("state = %+v", state[0])
	}
	if errs := errorsIn(t, resp); len(errs) != 0 {
		t.Errorf("errors = %v, want none: nothing was decrypted", errs)
	}
}

// Reported, not silently a shorter list: the broker cannot see this directory
// and has no other way to learn the entry named nothing.
func TestGetStateReportsAFileItCannotStat(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.sops.yaml")
	k := &Keeper{
		config: &config.Config{Secret: config.SecretConfig{Patterns: []string{missing}}},
		Keys:   newKeyHolder(config.KeeperConfig{}),
	}

	resp := handle(k, map[string]any{"op": "get_state"})
	if state := states(t, resp); len(state) != 0 {
		t.Errorf("state = %v, want empty", state)
	}
	absent := unresolved(t, resp)
	if len(absent) != 1 || !strings.Contains(absent[0], missing) {
		t.Errorf("unresolved = %v, want one naming %s", absent, missing)
	}
}

// Together, so the broker cannot cache a value set under a fingerprint taken at
// another moment and miss the edit between them.
func TestGetValuesCarriesTheFileState(t *testing.T) {
	secrets, keys := fixture(t, sopstest.Branch{{Key: "flat", Value: "s3cr3t-value-here"}})
	k := &Keeper{config: &config.Config{Secret: secrets}, Keys: keys}

	resp := handle(k, map[string]any{"op": "get_values"})
	values, ok := resp["values"].(map[string]string)
	if !ok || values["flat"] != "s3cr3t-value-here" {
		t.Fatalf("values = %v", resp["values"])
	}
	state, ok := resp["state"].([]FileState)
	if !ok || len(state) != len(secrets.Patterns) {
		t.Fatalf("state = %v, want one per managed file", resp["state"])
	}
	if state[0].Path != secrets.Patterns[0] {
		t.Errorf("state names %q, want %q", state[0].Path, secrets.Patterns[0])
	}
}

// The keeper and the broker are one binary under two units. A caller of another
// release is one of them left running across the install that replaced it, and
// is refused before the op: the alternative is serving the value set to a
// broker built against a different response shape. Sent to Handle rather than
// through the test helper, which fills the field in.
func TestARequestOfAnotherReleaseIsRefused(t *testing.T) {
	k := &Keeper{config: &config.Config{}, Keys: newKeyHolder(config.KeeperConfig{})}
	for _, probe := range []struct{ name, caller string }{
		{"an older release", "0.1.4"},
		{"none, which is what a client built before the field sends", ""},
	} {
		t.Run(probe.name, func(t *testing.T) {
			request := map[string]any{"op": "get_values"}
			if probe.caller != "" {
				request["version"] = probe.caller
			}
			resp := k.Handle(request)
			errObj, ok := resp["error"].(map[string]string)
			if !ok {
				t.Fatalf("not refused: %v", resp)
			}
			if errObj["code"] != "bad_request" {
				t.Errorf("code = %q, want bad_request", errObj["code"])
			}
			if !strings.Contains(errObj["message"], version.Version) {
				t.Errorf("the refusal does not name this release: %s", errObj["message"])
			}
			if _, leaked := resp["values"]; leaked {
				t.Error("a refused request came back with values")
			}
		})
	}
}
