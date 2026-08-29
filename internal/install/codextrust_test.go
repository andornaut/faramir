package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	codexAccountHookHash = "sha256:d0dd8643cb752f595e5c6b4e111da2128666bd0c6c66f5b3d0e4365eeacf7907"
	codexTreeHookHash    = "sha256:1c5598a904eb33a91c90a8790392a5d43d5df6c5a89dc0b9d407f8215db99234"
)

// codexStar is the matcher both halves register under, addressable so a test
// can pass it where Codex passes an option.
func codexStar() *string {
	return new("*")
}

// codexTimeout is the timeout the assets set, addressable for the same reason.
func codexTimeout(seconds int64) *int64 {
	return new(seconds)
}

// The hash faramir computes is the one Codex records, or every hook reads as
// modified and doctor fails a host that is doing its job. Both halves, the two
// differing only in the approval flag.
func TestCodexTrustHashIsWhatCodexRecords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "the account-wide hook",
			command: DefaultBinDir + "/faramir guard --host codex --deny-only",
			want:    codexAccountHookHash,
		},
		{
			name:    "the tree's hook",
			command: DefaultBinDir + "/faramir guard --host codex",
			want:    codexTreeHookHash,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := codexTrustHash(codexStar(), codexHandler{
				Type: "command", Command: tc.command, Timeout: codexTimeout(10),
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
	target := agentTargets["codex"]
	for _, tc := range []struct {
		file agentFile
		want string
	}{
		{target.accountFiles[0], codexAccountHookHash},
		{target.files[0], codexTreeHookHash},
	} {
		body, err := assetFor(target, tc.file, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		var doc codexHooksFileDoc
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s is not JSON Codex can read: %v", tc.file.path, err)
		}
		group := doc.Hooks.PreToolUse[0]
		got, err := codexTrustHash(group.Matcher, group.Hooks[0])
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s hashes to %s, want %s. If the asset changed on purpose, "+
				"every enrolled tree has to be trusted again and the recorded "+
				"identity here has to be taken from Codex", tc.file.path, got, tc.want)
		}
	}
}

// What Codex fills in before it hashes. Each of these is a way two files
// spelling the same hook would otherwise hash apart, or a way two different
// hooks would hash alike.
func TestCodexTrustHashNormalizesTheHookCodexParsed(t *testing.T) {
	base := codexHandler{Type: "command", Command: "/usr/local/bin/faramir guard --host codex"}
	hash := func(t *testing.T, matcher *string, handler codexHandler) string {
		t.Helper()
		got, err := codexTrustHash(matcher, handler)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	withDefaultTimeout := base
	withDefaultTimeout.Timeout = codexTimeout(codexDefaultHookTimeout)
	if hash(t, codexStar(), base) != hash(t, codexStar(), withDefaultTimeout) {
		t.Error("an absent timeout does not hash as 600, so a hook Codex trusts " +
			"reads as modified")
	}

	zero, one := base, base
	zero.Timeout, one.Timeout = codexTimeout(0), codexTimeout(1)
	if hash(t, codexStar(), zero) != hash(t, codexStar(), one) {
		t.Error("a zero timeout does not hash as one second, which is what Codex " +
			"raises it to")
	}

	limited, defaulted := base, base
	limited.AdditionalContextLimit = codexTimeout(codexDefaultContextLimit)
	if hash(t, codexStar(), limited) != hash(t, codexStar(), defaulted) {
		t.Error("a context limit equal to the default does not hash as an absent " +
			"one, which is what Codex drops it to")
	}

	// And the fields that do separate two hooks. A hash that ignored one of
	// these would call a rewritten hook trusted.
	async := base
	async.Async = true
	if hash(t, codexStar(), async) == hash(t, codexStar(), base) {
		t.Error("an async hook hashes as a synchronous one")
	}
	other := base
	other.Command += " --deny-only"
	if hash(t, codexStar(), other) == hash(t, codexStar(), base) {
		t.Error("two commands hash alike, so a hook rewritten to approve every " +
			"command reads as the trusted one")
	}
	if hash(t, nil, base) == hash(t, codexStar(), base) {
		t.Error("a hook matching every tool hashes as one matching none")
	}
}

// A hooks file is merged rather than written whole, so faramir's registration
// sits wherever the operator's own hooks leave room, and Codex keys trust by
// that position. A key built from an assumed position names a hook nobody
// trusted.
func TestCodexGuardHooksAreKeyedByWhereTheySit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	writeCodexHooks(t, path, `{
	  "hooks": {
	    "PreToolUse": [
	      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/audit", "timeout": 5}]},
	      {"matcher": "*", "hooks": [
	        {"type": "command", "command": "/opt/notify"},
	        {"type": "command", "command": "`+DefaultBinDir+`/faramir guard --host codex", "timeout": 10}
	      ]}
	    ]
	  }
	}`)

	hooks, err := codexGuardHooks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 {
		t.Fatalf("found %d guard hook(s) in a file carrying one", len(hooks))
	}
	if want := path + ":pre_tool_use:1:1"; hooks[0].Key != want {
		t.Errorf("key = %q, want %q", hooks[0].Key, want)
	}
	if hooks[0].Hash != codexTreeHookHash {
		t.Errorf("hash = %s, want %s", hooks[0].Hash, codexTreeHookHash)
	}
}

// Every way a hook that is installed does not run, and the one way it does.
// Each of the three failures leaves Codex working normally and refusing
// nothing, which is why none of them is a warning.
func TestReportCodexTrust(t *testing.T) {
	for _, tc := range []struct {
		name string
		// state is the [hooks.state] entry written for the account-wide hook,
		// rendered against its key. Empty writes no config at all.
		state string
		want  Status
		says  []string
	}{
		{
			name:  "trusted",
			state: "trusted_hash = \"" + codexAccountHookHash + "\"\n",
			want:  StatusOK, says: []string{"trusts"},
		},
		{
			name: "never trusted",
			want: StatusFailed,
			says: []string{"has not been told to trust", "skips them and says nothing"},
		},
		{
			name:  "trusted before the hook changed",
			state: "trusted_hash = \"sha256:0000\"\n",
			want:  StatusFailed, says: []string{"trusts a different hook"},
		},
		{
			name:  "trusted and turned off",
			state: "trusted_hash = \"" + codexAccountHookHash + "\"\nenabled = false\n",
			want:  StatusFailed, says: []string{"turned off", "enabled = false"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			hooks := filepath.Join(home, codexHooksFile)
			writeCodexHooks(t, hooks, `{
			  "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
			    {"type": "command", "command": "`+DefaultBinDir+`/faramir guard --host codex --deny-only", "timeout": 10}
			  ]}]}
			}`)
			if tc.state != "" {
				writeCodexHooks(t, filepath.Join(home, codexConfigFile),
					"[hooks.state.\""+hooks+":pre_tool_use:0:0\"]\n"+tc.state)
			}

			var report DoctorReport
			reportCodexTrust(&report, home, nil)

			finding := onlyFinding(t, report, "codex hook trust")
			if finding.Status != tc.want {
				t.Errorf("status = %q, want %q: %s", finding.Status, tc.want, finding.Detail)
			}
			for _, want := range tc.says {
				if !strings.Contains(finding.Detail, want) {
					t.Errorf("detail does not say %q: %s", want, finding.Detail)
				}
			}
		})
	}
}

// An enrolled tree's hook is trusted on its own key, so a host whose account
// hook is trusted and whose trees are not is a host where nothing is routed.
func TestReportCodexTrustAsksEveryEnrolledTree(t *testing.T) {
	home := t.TempDir()
	tree := t.TempDir()
	writeCodexHooks(t, filepath.Join(tree, codexHooksFile), `{
	  "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
	    {"type": "command", "command": "`+DefaultBinDir+`/faramir guard --host codex", "timeout": 10}
	  ]}]}
	}`)

	var report DoctorReport
	reportCodexTrust(&report, home, []EnrolledTree{{Dir: tree, Agents: []string{"codex"}}})

	finding := onlyFinding(t, report, "codex hook trust")
	if finding.Status != StatusFailed || !strings.Contains(finding.Detail, tree) {
		t.Errorf("an enrolled tree's untrusted hook was not reported: %q %s",
			finding.Status, finding.Detail)
	}
}

// A host that runs no Codex is not a host with a problem. Reported rather than
// left out: a check absent from the report is one an operator cannot tell from
// a check that passed.
func TestReportCodexTrustSaysNothingIsInstalled(t *testing.T) {
	var report DoctorReport
	reportCodexTrust(&report, t.TempDir(), nil)

	if finding := onlyFinding(t, report, "codex hook trust"); finding.Status != StatusNA {
		t.Errorf("status = %q, want %q: %s", finding.Status, StatusNA, finding.Detail)
	}
	if report.Failed {
		t.Error("a host that does not run Codex failed the report")
	}
}

// A tree enrolled for another agent carries no Codex hook, and a tree that has
// moved carries nothing at all. Neither is this check's finding.
func TestReportCodexTrustSkipsTreesWithoutACodexHook(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	writeCodexHooks(t, filepath.Join(other, codexHooksFile), `{"hooks": {"PreToolUse": []}}`)

	var report DoctorReport
	reportCodexTrust(&report, home, []EnrolledTree{
		{Dir: other, Agents: []string{"claude"}},
		{Dir: filepath.Join(home, "gone"), Agents: []string{"codex"}},
	})

	if finding := onlyFinding(t, report, "codex hook trust"); finding.Status != StatusNA {
		t.Errorf("status = %q, want %q: %s", finding.Status, StatusNA, finding.Detail)
	}
}

// writeCodexHooks writes one of Codex's own files, making its directory.
func writeCodexHooks(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
