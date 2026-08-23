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

func fixture(t *testing.T, branch sops.TreeBranch) (config.SecretConfig, *KeyHolder) {
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

func TestDecryptRoundTrip(t *testing.T) {
	secrets, keys := fixture(t, sops.TreeBranch{
		{Key: "router", Value: sops.TreeBranch{
			{Key: "admin", Value: "hunter2hunter2"},
		}},
		{Key: "flat", Value: "s3cr3t-value-here"},
		{Key: "enabled", Value: true},
	})

	values, errs, _ := DecryptAll(secrets, keys)
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

// The key reaches sops as a path, never as a value. Asserted against a real
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

	_, errs, _ := DecryptAll(config.SecretConfig{
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

	values, errs, _ := DecryptAll(secrets, keys)
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

	values, errs, _ := DecryptAll(secrets, keys)
	if len(errs) == 0 {
		t.Error("the broken file produced no error")
	}
	if values["good"] != "a-good-value-x" {
		t.Errorf("the good file was lost: %v", values)
	}
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
	secrets, keys := fixture(t, sops.TreeBranch{{Key: "flat", Value: "s3cr3t-value-here"}})
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

// Scrub works from the identity format, so it needs no copy of the key.
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
		// first install looks like. What makes it safe is that the value set is
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
// install looks like. The broker starts on it and refuses exec and redact
// while the value set is empty, and `--check` and `doctor` fail on it.
func TestAPatternThatNamesNothingIsReportedAsUnresolved(t *testing.T) {
	pattern := filepath.Join(t.TempDir(), "*.sops.yml")
	k := &Keeper{
		config: &config.Config{Secret: config.SecretConfig{Patterns: []string{pattern}}},
		Keys:   newKeyHolder(config.KeeperConfig{}),
	}

	resp := handle(k, map[string]any{"op": "get_state"})
	if state := states(t, resp); len(state) != 0 {
		t.Errorf("state = %v, want empty", state)
	}
	if errs := errorsIn(t, resp); len(errs) != 0 {
		t.Errorf("errors = %v, want none: naming nothing is not a load failure", errs)
	}
	absent := unresolved(t, resp)
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
		config: &config.Config{Secret: config.SecretConfig{
			Patterns: []string{filepath.Join(dir, "*.sops.yml")},
		}},
		Keys: newKeyHolder(config.KeeperConfig{}),
	}

	if state := states(t, handle(k, map[string]any{"op": "get_state"})); len(state) != 1 {
		t.Fatalf("state = %v, want the one file", state)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.sops.yml"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := states(t, handle(k, map[string]any{"op": "get_state"}))
	if len(state) != 2 {
		t.Errorf("state = %v, want both files without a reload of the config", state)
	}
}

// The store is one directory spelled once per extension a managed file may
// carry, so two of the three matching nothing is the ordinary case rather than
// a store two thirds missing. Reporting it would fail --check and doctor on
// every host that keeps only *.sops.yml, which is every host.
func TestUnmatchedExtensionsAreNotAMissingStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.sops.yml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, errs, unresolved := Resolve([]string{
		filepath.Join(dir, "*.sops.yml"),
		filepath.Join(dir, "*.sops.yaml"),
		filepath.Join(dir, "*.sops.json"),
	})
	if len(paths) != 1 {
		t.Fatalf("paths = %v, want the one file", paths)
	}
	if len(errs) != 0 || len(unresolved) != 0 {
		t.Errorf("errors = %v, unresolved = %v, want neither", errs, unresolved)
	}
}

// A store that matched nothing at all is still reported: that is a broker
// redacting nothing, and it has to be told from files not written yet.
func TestAStoreThatMatchedNothingIsStillReported(t *testing.T) {
	dir := t.TempDir()
	_, _, unresolved := Resolve([]string{filepath.Join(dir, "*.sops.yml")})
	if len(unresolved) != 1 {
		t.Errorf("unresolved = %v, want the entry that named nothing", unresolved)
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

// twoFiles is a store of two managed files, which is what a shadowed ref needs.
// Patterns names them in a fixed order, so which value wins is the test's to
// decide rather than the filesystem's.
func twoFiles(t *testing.T, first, second sops.TreeBranch) (config.SecretConfig, *KeyHolder) {
	t.Helper()
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	firstPath := filepath.Join(dir, "a.sops.yaml")
	secondPath := filepath.Join(dir, "b.sops.yaml")
	sopstest.WriteEncrypted(t, firstPath, recipient, first)
	sopstest.WriteEncrypted(t, secondPath, recipient, second)

	return config.SecretConfig{
			Patterns:       []string{firstPath, secondPath},
			DecryptCommand: sopstest.DecryptCommand(t),
		},
		newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath})
}

// A ref two files disagree about: one value wins and the other is in no
// redactor, which is a value on this host a command can print in the clear. It
// is reported with both files, the repair being to take the ref out of one.
func TestARefTwoFilesDisagreeAboutIsReported(t *testing.T) {
	secrets, keys := twoFiles(t,
		sops.TreeBranch{{Key: "token", Value: "value-from-the-first-file"}},
		sops.TreeBranch{{Key: "token", Value: "value-from-the-second-file"}})

	values, errs, shadowed := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if got := values["token"]; got != "value-from-the-second-file" {
		t.Errorf("token = %q, want the last file read to win", got)
	}
	detail, ok := shadowed["token"]
	if !ok {
		t.Fatalf("a ref two files disagree about was not reported: %v", shadowed)
	}
	for _, want := range []string{"a.sops.yaml", "b.sops.yaml"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the report does not name %s, so the repair is not in it: %q", want, detail)
		}
	}
}

// The same ref in two files holding the same value is not shadowed. Nothing is
// lost: the value that does not win is byte for byte the one that does, so it
// is in the redactor and injected by the same ref. Reporting it failed
// `broker --check` and `doctor` on a host with nothing wrong with it.
func TestTheSameValueInTwoFilesIsNotShadowed(t *testing.T) {
	secrets, keys := twoFiles(t,
		sops.TreeBranch{{Key: "token", Value: "the-very-same-value-here"}},
		sops.TreeBranch{{Key: "token", Value: "the-very-same-value-here"}})

	values, errs, shadowed := DecryptAll(secrets, keys)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if got := values["token"]; got != "the-very-same-value-here" {
		t.Errorf("token = %q", got)
	}
	if len(shadowed) != 0 {
		t.Errorf("two files holding one value were reported as shadowed: %v", shadowed)
	}
}

// Three files, the middle one agreeing and the last differing: the disagreement
// is found wherever in the read order it falls, and every file that defines the
// ref is named.
func TestADisagreementIsFoundWhereverItFalls(t *testing.T) {
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	written := []string{"same-value-for-this-ref", "same-value-for-this-ref", "a-different-value-here"}
	paths := make([]string, 0, len(written))
	for i, value := range written {
		path := filepath.Join(dir, string(rune('a'+i))+".sops.yaml")
		sopstest.WriteEncrypted(t, path, recipient,
			sops.TreeBranch{{Key: "token", Value: value}})
		paths = append(paths, path)
	}
	secrets := config.SecretConfig{Patterns: paths, DecryptCommand: sopstest.DecryptCommand(t)}

	_, errs, shadowed := DecryptAll(secrets, newKeyHolder(config.KeeperConfig{AgeKeyFile: keyPath}))
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	detail, ok := shadowed["token"]
	if !ok {
		t.Fatalf("a disagreement in the third file was not reported: %v", shadowed)
	}
	for _, want := range []string{"a.sops.yaml", "b.sops.yaml", "c.sops.yaml"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the report does not name %s: %q", want, detail)
		}
	}
}
