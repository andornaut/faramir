package codextrust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// Codex skips a hook it has not been told to trust and says nothing when it
// does, so an unguarded Codex is indistinguishable from a guarded one except by
// asking what it trusts. What these cover is the asking: the identity faramir
// computes being the one Codex records, and each way a hook ends up loaded and
// never run.

// The identities Codex 0.151.0 recorded for the two halves of an enrolment, as
// the shipped assets render them at the default bin directory: matcher "*",
// timeout 10, async unset. Golden because the identity is Codex's to define and
// nothing in this repository can derive it: an encoding that drifts from these
// would report a trusted hook as modified on every host.
const (
	accountHookHash = "sha256:d0dd8643cb752f595e5c6b4e111da2128666bd0c6c66f5b3d0e4365eeacf7907"
	treeHookHash    = "sha256:1c5598a904eb33a91c90a8790392a5d43d5df6c5a89dc0b9d407f8215db99234"
)

// star is the matcher both halves register under, addressable so a test can
// pass it where Codex passes an option.
func star() *string {
	return new("*")
}

// seconds is the timeout the assets set, addressable for the same reason.
func seconds(count int64) *int64 {
	return new(count)
}

// The hash faramir computes is the one Codex records, or every hook reads as
// modified and doctor fails a host that is doing its job. Both halves, the two
// differing only in the approval flag.
func TestTrustHashIsWhatCodexRecords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "the account-wide hook",
			command: hostlayout.DefaultBinDir + "/faramir guard --host codex --deny-only",
			want:    accountHookHash,
		},
		{
			name:    "the tree's hook",
			command: hostlayout.DefaultBinDir + "/faramir guard --host codex",
			want:    treeHookHash,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := trustHash(star(), handler{
				Type: "command", Command: tc.command, Timeout: seconds(10),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("hash = %s, want %s: Codex would report this hook as modified "+
					"on every host that trusts it", got, tc.want)
			}
		})
	}
}

// The assets are what an enrolment installs, so a change to either one drops
// trust wherever it was granted. Asserted against the same two identities the
// hash test names: the two are one claim, and a template edited without the
// constants moving would otherwise pass here and fail on every host.
func TestTheShippedCodexHooksHashToWhatIsRecorded(t *testing.T) {
	target := agentcfg.Targets["codex"]
	for _, tc := range []struct {
		file agentcfg.File
		want string
	}{
		{target.AccountFiles[0], accountHookHash},
		{target.Files[0], treeHookHash},
	} {
		body, err := agentcfg.AssetFor(target, tc.file, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		var doc hooksFileDoc
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s is not JSON Codex can read: %v", tc.file.Path, err)
		}
		group := doc.Hooks.PreToolUse[0]
		got, err := trustHash(group.Matcher, group.Hooks[0])
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s hashes to %s, want %s. If the asset changed on purpose, "+
				"every enrolled tree has to be trusted again and the recorded "+
				"identity here has to be taken from Codex", tc.file.Path, got, tc.want)
		}
	}
}

// What Codex fills in before it hashes. Each of these is a way two files
// spelling the same hook would otherwise hash apart, or a way two different
// hooks would hash alike.
func TestTrustHashNormalizesTheHookCodexParsed(t *testing.T) {
	base := handler{Type: "command", Command: "/usr/local/bin/faramir guard --host codex"}
	hash := func(t *testing.T, matcher *string, hook handler) string {
		t.Helper()
		got, err := trustHash(matcher, hook)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	withDefaultTimeout := base
	withDefaultTimeout.Timeout = seconds(defaultHookTimeout)
	if hash(t, star(), base) != hash(t, star(), withDefaultTimeout) {
		t.Error("an absent timeout does not hash as 600, so a hook Codex trusts " +
			"reads as modified")
	}

	zero, one := base, base
	zero.Timeout, one.Timeout = seconds(0), seconds(1)
	if hash(t, star(), zero) != hash(t, star(), one) {
		t.Error("a zero timeout does not hash as one second, which is what Codex " +
			"raises it to")
	}

	limited, defaulted := base, base
	limited.AdditionalContextLimit = seconds(defaultContextLimit)
	if hash(t, star(), limited) != hash(t, star(), defaulted) {
		t.Error("a context limit equal to the default does not hash as an absent " +
			"one, which is what Codex drops it to")
	}

	// And the fields that do separate two hooks. A hash that ignored one of
	// these would call a rewritten hook trusted.
	async := base
	async.Async = true
	if hash(t, star(), async) == hash(t, star(), base) {
		t.Error("an async hook hashes as a synchronous one")
	}
	other := base
	other.Command += " --deny-only"
	if hash(t, star(), other) == hash(t, star(), base) {
		t.Error("two commands hash alike, so a hook rewritten to approve every " +
			"command reads as the trusted one")
	}
	if hash(t, nil, base) == hash(t, star(), base) {
		t.Error("a hook matching every tool hashes as one matching none")
	}
}

// A hooks file is merged rather than written whole, so faramir's registration
// sits wherever the operator's own hooks leave room, and Codex keys trust by
// that position. A key built from an assumed position names a hook nobody
// trusted.
func TestGuardHooksAreKeyedByWhereTheySit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	writeCodexFile(t, path, `{
	  "hooks": {
	    "PreToolUse": [
	      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/audit", "timeout": 5}]},
	      {"matcher": "*", "hooks": [
	        {"type": "command", "command": "/opt/notify"},
	        {"type": "command", "command": "`+hostlayout.DefaultBinDir+`/faramir guard --host codex", "timeout": 10}
	      ]}
	    ]
	  }
	}`)

	hooks, err := GuardHooks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 {
		t.Fatalf("found %d guard hook(s) in a file carrying one", len(hooks))
	}
	if want := path + ":pre_tool_use:1:1"; hooks[0].Key != want {
		t.Errorf("key = %q, want %q", hooks[0].Key, want)
	}
	if hooks[0].Hash != treeHookHash {
		t.Errorf("hash = %s, want %s", hooks[0].Hash, treeHookHash)
	}
}

// Every way a hook ends up not running keeps the note, so an operator is never
// told nothing by a hook Codex skips. Against one scope, the second one being
// its own test below.
func TestNoteStandsForEveryWayAHookDoesNotRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		// state is the [hooks.state] entry for the tree's hook, rendered against
		// its key. Nil writes no config at all, which is an account that has
		// trusted nothing.
		state func(hash string) string
		// hooks replaces the tree's hook file, empty leaving the guard hook there.
		hooks string
		want  bool
	}{
		{
			name:  "trusted",
			state: func(hash string) string { return "trusted_hash = \"" + hash + "\"\n" },
			want:  false,
		},
		{
			name: "never trusted",
			want: true,
		},
		{
			name:  "trusted before the hook changed",
			state: func(string) string { return "trusted_hash = \"sha256:0000\"\n" },
			want:  true,
		},
		{
			name: "trusted and turned off",
			state: func(hash string) string {
				return "trusted_hash = \"" + hash + "\"\nenabled = false\n"
			},
			want: true,
		},
		{
			// Nothing this note asks for is on disk, which is another warning's
			// finding and not this one's answer: said rather than left out, an
			// operator told nothing takes it for a tree that is covered.
			name:  "no guard hook left in the file",
			hooks: `{"hooks": {"PreToolUse": []}}`,
			state: func(hash string) string { return "trusted_hash = \"" + hash + "\"\n" },
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, dir := t.TempDir(), t.TempDir()
			hooks := writeTreeHook(t, dir)
			if tc.state != nil {
				writeTrust(t, home, trustEntry{hooks, tc.state(guardHash(t, hooks))})
			}
			if tc.hooks != "" {
				writeCodexFile(t, hooks, tc.hooks)
			}
			if got := NoteStands("codex", home, dir); got != tc.want {
				t.Errorf("NoteStands = %v, want %v", got, tc.want)
			}
		})
	}
}

// The two halves of an enrolment are rendered from separate assets and trusted
// on separate keys, so a run that asked about one of them would go quiet while
// Codex skips the other.
func TestNoteStandsWhileAnyScopeIsUntrusted(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	account := writeAccountHook(t, home)
	tree := writeTreeHook(t, dir)

	writeTrust(t, home, trustEntry{tree, "trusted_hash = \"" + guardHash(t, tree) + "\"\n"})
	if !NoteStands("codex", home, dir, home) {
		t.Error("a trusted tree answered for an untrusted account-wide hook, " +
			"whose deny rules cover every directory the agent works in")
	}
	writeTrust(t, home,
		trustEntry{tree, "trusted_hash = \"" + guardHash(t, tree) + "\"\n"},
		trustEntry{account, "trusted_hash = \"" + guardHash(t, account) + "\"\n"})
	if NoteStands("codex", home, dir, home) {
		t.Error("the note is still said to an operator who has trusted both halves")
	}
}

// A scope carrying no hook is not an answer either way, so a run that wrote
// nothing Codex can be told to trust says what it always said.
func TestNoteStandsWithoutAHookFile(t *testing.T) {
	if !NoteStands("codex", t.TempDir(), t.TempDir()) {
		t.Error("a run that wrote no Codex hook was taken for one whose hooks " +
			"are trusted")
	}
}

// An unresolved home would otherwise be joined into a relative path, and what
// Codex trusts would be read from the tree being enrolled: a .codex/config.toml
// committed to a project could then silence the note for that project.
func TestNoteStandsWithoutAHome(t *testing.T) {
	dir := t.TempDir()
	hooks := writeTreeHook(t, dir)
	writeTrust(t, dir, trustEntry{hooks, "trusted_hash = \"" + guardHash(t, hooks) + "\"\n"})

	if !NoteStands("codex", "", dir) {
		t.Error("a config inside the tree answered for the account's, so a " +
			"project can silence the note for itself")
	}
}

// Every other agent's note describes what its enrolment is rather than a
// condition anything records, so nothing here can answer one.
func TestNoteStandsForEveryOtherAgent(t *testing.T) {
	if !NoteStands("antigravity", t.TempDir(), t.TempDir()) {
		t.Error("another agent's note was answered by what Codex records")
	}
}

// trustEntry is one hook file and what Codex records against it.
type trustEntry struct {
	hooks string
	body  string
}

// writeTrust writes Codex's config, one [hooks.state] entry per hook file.
func writeTrust(t *testing.T, home string, entries ...trustEntry) {
	t.Helper()
	var body strings.Builder
	for _, entry := range entries {
		body.WriteString("[hooks.state.\"" + entry.hooks + ":pre_tool_use:0:0\"]\n")
		body.WriteString(entry.body)
	}
	writeCodexFile(t, filepath.Join(home, ConfigFile), body.String())
}

// guardHash is the identity Codex would record for the one guard hook in this
// file, read back rather than written down: a test that spelled the hash itself
// would assert the encoding twice and the classification not at all.
func guardHash(t *testing.T, path string) string {
	t.Helper()
	hooks, err := GuardHooks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 {
		t.Fatalf("found %d guard hook(s) in a file carrying one", len(hooks))
	}
	return hooks[0].Hash
}

// writeAccountHook writes the deny-only hook `init` leaves under a home, and
// names it.
func writeAccountHook(t *testing.T, home string) string {
	t.Helper()
	path := filepath.Join(home, agentcfg.CodexHooksFile)
	writeCodexFile(t, path, `{
	  "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
	    {"type": "command", "command": "`+hostlayout.DefaultBinDir+`/faramir guard --host codex --deny-only", "timeout": 10}
	  ]}]}
	}`)
	return path
}

// writeTreeHook writes the hook an enrolment leaves in a tree, and names it.
func writeTreeHook(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, agentcfg.CodexHooksFile)
	writeCodexFile(t, path, `{
	  "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
	    {"type": "command", "command": "`+hostlayout.DefaultBinDir+`/faramir guard --host codex", "timeout": 10}
	  ]}]}
	}`)
	return path
}

// writeCodexFile writes one of Codex's own files, making its directory.
func writeCodexFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
