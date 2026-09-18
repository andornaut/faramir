package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/codextrust"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// Codex skips a hook it has not been told to trust and says nothing when it
// does, so an unguarded Codex is indistinguishable from a guarded one except by
// asking what it trusts. What these cover is the finding: each way a hook ends
// up loaded and never run, told apart. The identity Codex records is
// internal/codextrust's.

// Every way a hook that is installed does not run, and the one way it does.
// Each of the three failures leaves Codex working normally and refusing
// nothing, which is why none of them is a warning.
func TestReportCodexTrust(t *testing.T) {
	for _, tc := range []struct {
		name string
		// state is the [hooks.state] entry written for the account-wide hook,
		// rendered against the identity Codex would record for it. Nil writes no
		// config at all.
		state func(hash string) string
		want  Status
		says  []string
	}{
		{
			name:  "trusted",
			state: func(hash string) string { return "trusted_hash = \"" + hash + "\"\n" },
			want:  StatusOK, says: []string{"trusts"},
		},
		{
			name: "never trusted",
			want: StatusFailed,
			says: []string{"has not been told to trust", "skips them and says nothing"},
		},
		{
			name:  "trusted before the hook changed",
			state: func(string) string { return "trusted_hash = \"sha256:0000\"\n" },
			want:  StatusFailed, says: []string{"trusts a different hook"},
		},
		{
			name: "trusted and turned off",
			state: func(hash string) string {
				return "trusted_hash = \"" + hash + "\"\nenabled = false\n"
			},
			want: StatusFailed, says: []string{"turned off", "enabled = false"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			hooks := filepath.Join(home, agentcfg.CodexHooksFile)
			writeCodexHooks(t, hooks, `{
			  "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
			    {"type": "command", "command": "`+hostlayout.DefaultBinDir+`/faramir guard --host codex --deny-only", "timeout": 10}
			  ]}]}
			}`)
			if tc.state != nil {
				writeCodexHooks(t, filepath.Join(home, codextrust.ConfigFile),
					"[hooks.state.\""+hooks+":pre_tool_use:0:0\"]\n"+tc.state(guardHash(t, hooks)))
			}

			var report Report
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
	writeCodexHooks(t, filepath.Join(tree, agentcfg.CodexHooksFile), `{
	  "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
	    {"type": "command", "command": "`+hostlayout.DefaultBinDir+`/faramir guard --host codex", "timeout": 10}
	  ]}]}
	}`)

	var report Report
	reportCodexTrust(&report, home, []agentcfg.EnrolledTree{{Dir: tree, Agents: []string{"codex"}}})

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
	var report Report
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
	writeCodexHooks(t, filepath.Join(other, agentcfg.CodexHooksFile), `{"hooks": {"PreToolUse": []}}`)

	var report Report
	reportCodexTrust(&report, home, []agentcfg.EnrolledTree{
		{Dir: other, Agents: []string{"claude"}},
		{Dir: filepath.Join(home, "gone"), Agents: []string{"codex"}},
	})

	if finding := onlyFinding(t, report, "codex hook trust"); finding.Status != StatusNA {
		t.Errorf("status = %q, want %q: %s", finding.Status, StatusNA, finding.Detail)
	}
}

// guardHash is the identity Codex would record for the one guard hook in this
// file, read back rather than written down: what the encoding has to be is
// internal/codextrust's to assert, and these cover what is done with it.
func guardHash(t *testing.T, path string) string {
	t.Helper()
	hooks, err := codextrust.GuardHooks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 {
		t.Fatalf("found %d guard hook(s) in a file carrying one", len(hooks))
	}
	return hooks[0].Hash
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
