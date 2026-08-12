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
			Patterns:       []string{secretPath},
			DecryptCommand: sopstest.DecryptCommand(t),
		},
		newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
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
	// "true"/"false" would redact half the output.
	if _, ok := values["enabled"]; ok {
		t.Errorf("boolean leaked into the value set: %v", values)
	}
	for ref := range values {
		if ref == "sops" || strings.HasPrefix(ref, "sops/") {
			t.Errorf("sops metadata leaked into the value set: %s", ref)
		}
	}
}

// The key reaches sops as a path, never as a value.  Asserted against a real
// child's environment rather than against the keeper's intent.
func TestTheDecryptChildIsGivenTheKeyPathAndNotTheKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := sopstest.NewIdentity(t, dir)
	managed := filepath.Join(dir, "vault.sops.yaml")
	if err := os.WriteFile(managed, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Dumps what it was handed and answers with an empty tree, so the run
	// succeeds and the environment is what is left to look at.
	dump := filepath.Join(dir, "environ")
	script := filepath.Join(dir, "decrypt")
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\nprintenv > "+dump+"\necho '{}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, errs := DecryptAll(config.SecretsConfig{
		Patterns: []string{managed}, DecryptCommand: []string{script, "{file}"},
	}, newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath}))
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}

	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	environ := string(raw)
	if !strings.Contains(environ, "SOPS_AGE_KEY_FILE="+keyPath) {
		t.Errorf("the child was not told where the key is:\n%s", environ)
	}
	for line := range strings.SplitSeq(environ, "\n") {
		if strings.HasPrefix(line, "SOPS_AGE_KEY=") {
			t.Error("KEY MATERIAL IN THE CHILD'S ENVIRONMENT: SOPS_AGE_KEY was set")
		}
	}
	// And the material itself, whatever variable carried it.
	identity, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(identity))
	if !strings.HasPrefix(body, "AGE-SECRET-KEY") {
		t.Fatalf("fixture is not an age identity: %q", body)
	}
	if strings.Contains(environ, body) {
		t.Error("KEY MATERIAL IN THE CHILD'S ENVIRONMENT: the identity itself was passed")
	}
}

// An empty value set means nothing is redacted, so this fails loudly.
func TestWrongIdentityFails(t *testing.T) {
	secrets, _ := fixture(t, sops.TreeBranch{{Key: "token", Value: "value-goes-here"}})

	other := t.TempDir()
	wrongKey, _ := sopstest.NewIdentity(t, other)
	keys := newKeyHolder(config.KeeperConfig{AgeKeyFile: wrongKey})

	values, errs := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Fatal("decrypting with the wrong identity reported no error")
	}
	if len(values) != 0 {
		t.Errorf("values were returned anyway: %v", values)
	}
}

func TestOneBadFileDoesNotBlankTheSet(t *testing.T) {
	secrets, keys := fixture(t, sops.TreeBranch{{Key: "good", Value: "a-good-value-x"}})
	broken := filepath.Join(t.TempDir(), "broken.sops.yaml")
	if err := os.WriteFile(broken, []byte("not: sops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets.Patterns = append(secrets.Patterns, broken)

	values, errs := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Error("the broken file produced no error")
	}
	if values["good"] != "a-good-value-x" {
		t.Errorf("the good file was lost: %v", values)
	}
}

// get_values and get_state, and nothing else.
func TestKeeperRefusesEveryOtherOp(t *testing.T) {
	k := &Keeper{config: &config.Config{}, Keys: newKeyHolder(config.KeeperConfig{})}
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

// The poll answers without the key and without execing sops, so a keeper that
// cannot decrypt still reports edits.
func TestGetStateFingerprintsWithoutDecrypting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.sops.yaml")
	if err := os.WriteFile(path, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &Keeper{
		config: &config.Config{Secrets: config.SecretsConfig{
			Patterns:       []string{path},
			DecryptCommand: []string{"/nonexistent/sops", "{file}"},
		}},
		Keys: newKeyHolder(config.KeeperConfig{}),
	}

	resp := k.Handle(map[string]any{"op": "get_state"})
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
	if errs := resp["errors"].([]string); len(errs) != 0 {
		t.Errorf("errors = %v, want none: nothing was decrypted", errs)
	}
}

// Reported, not silently a shorter list: the broker cannot see this directory
// and has no other way to learn the entry named nothing.
func TestGetStateReportsAFileItCannotStat(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.sops.yaml")
	k := &Keeper{
		config: &config.Config{Secrets: config.SecretsConfig{Patterns: []string{missing}}},
		Keys:   newKeyHolder(config.KeeperConfig{}),
	}

	resp := k.Handle(map[string]any{"op": "get_state"})
	if state := resp["state"].([]FileState); len(state) != 0 {
		t.Errorf("state = %v, want empty", state)
	}
	absent := resp["unresolved_patterns"].([]string)
	if len(absent) != 1 || !strings.Contains(absent[0], missing) {
		t.Errorf("unresolved = %v, want one naming %s", absent, missing)
	}
}

// Together, so the broker cannot cache a value set under a fingerprint taken at
// another moment and miss the edit between them.
func TestGetValuesCarriesTheFileState(t *testing.T) {
	secrets, keys := fixture(t, sops.TreeBranch{{Key: "flat", Value: "s3cr3t-value-here"}})
	k := &Keeper{config: &config.Config{Secrets: secrets}, Keys: keys}

	resp := k.Handle(map[string]any{"op": "get_values"})
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

	keys := newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
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

// One rule for globs and literal paths alike: an entry naming nothing is an
// error.
func TestResolveExpandsPatternsAndLiterals(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.sops.yml", "b.sops.yml", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	glob := filepath.Join(dir, "*.sops.yml")
	literal := filepath.Join(dir, "a.sops.yml")
	missing := filepath.Join(dir, "gone.sops.yml")

	for _, tc := range []struct {
		name           string
		entries        []string
		wantPaths      []string
		wantErrs       int
		wantUnresolved int
	}{
		{"a pattern", []string{glob},
			[]string{filepath.Join(dir, "a.sops.yml"), filepath.Join(dir, "b.sops.yml")}, 0, 0},
		{"a literal", []string{literal}, []string{literal}, 0, 0},
		// Decrypting twice would report every ref in it as doubly defined.
		{"a pattern and a literal inside it", []string{glob, literal},
			[]string{filepath.Join(dir, "a.sops.yml"), filepath.Join(dir, "b.sops.yml")}, 0, 0},
		// Named nothing rather than failed: a store not written yet is what every
		// first install looks like.  What makes it safe is that the value set is
		// then empty, and exec and redact are refused while it is.
		{"a literal that is not there", []string{missing}, []string{}, 0, 1},
		{"a pattern that matches nothing",
			[]string{filepath.Join(dir, "*.sops.yaml")}, []string{}, 0, 1},
		{"a directory that is not there",
			[]string{filepath.Join(dir, "absent", "*.sops.yml")}, []string{}, 0, 1},
		{"nothing configured", nil, []string{}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, errs, unresolvedEntries := Resolve(tc.entries)
			if len(paths) != len(tc.wantPaths) {
				t.Fatalf("paths = %v, want %v", paths, tc.wantPaths)
			}
			for i, want := range tc.wantPaths {
				if paths[i] != want {
					t.Errorf("paths[%d] = %q, want %q", i, paths[i], want)
				}
			}
			if len(errs) != tc.wantErrs {
				t.Errorf("errors = %v, want %d", errs, tc.wantErrs)
			}
			if len(unresolvedEntries) != tc.wantUnresolved {
				t.Errorf("unresolved = %v, want %d", unresolvedEntries, tc.wantUnresolved)
			}
		})
	}
}

// Reported apart from the errors, an entry naming nothing being what a first
// install looks like.  The broker starts on it and refuses exec and redact
// while the value set is empty, and `--check` and `doctor` fail on it.
func TestAPatternThatNamesNothingIsReportedAsUnresolved(t *testing.T) {
	pattern := filepath.Join(t.TempDir(), "*.sops.yml")
	k := &Keeper{
		config: &config.Config{Secrets: config.SecretsConfig{Patterns: []string{pattern}}},
		Keys:   newKeyHolder(config.KeeperConfig{}),
	}

	resp := k.Handle(map[string]any{"op": "get_state"})
	if state := resp["state"].([]FileState); len(state) != 0 {
		t.Errorf("state = %v, want empty", state)
	}
	if errs := resp["errors"].([]string); len(errs) != 0 {
		t.Errorf("errors = %v, want none: naming nothing is not a load failure", errs)
	}
	absent := resp["unresolved_patterns"].([]string)
	if len(absent) != 1 || !strings.Contains(absent[0], "matched no files") {
		t.Errorf("unresolved = %v, want one saying the pattern matched no files", absent)
	}
}

// Picked up with nothing edited and no daemon restarted, which is why the
// expansion happens per request.
func TestAFileAddedToTheStoreIsPickedUp(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.sops.yml")
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &Keeper{
		config: &config.Config{Secrets: config.SecretsConfig{
			Patterns: []string{filepath.Join(dir, "*.sops.yml")},
		}},
		Keys: newKeyHolder(config.KeeperConfig{}),
	}

	if state := k.Handle(map[string]any{"op": "get_state"})["state"].([]FileState); len(state) != 1 {
		t.Fatalf("state = %v, want the one file", state)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.sops.yml"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := k.Handle(map[string]any{"op": "get_state"})["state"].([]FileState)
	if len(state) != 2 {
		t.Errorf("state = %v, want both files without a reload of the config", state)
	}
}
