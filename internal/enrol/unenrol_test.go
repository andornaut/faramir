package enrol

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

func unenrolFixture(t *testing.T, recorded bool) UnenrolOptions {
	t.Helper()
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || account.Username == "root" {
		t.Fatal("run these synthetic filesystem tests as an unprivileged container user")
	}
	opts := UnenrolOptions{Dir: t.TempDir(), ConfigDir: t.TempDir(), AgentUser: account.Username}
	writeUnenrolFile(t, opts.Dir, agentcfg.ProjectInstructions,
		"# Project\n\nUser prose.\n\n"+agentcfg.SectionBegin+"\nmanaged\n"+agentcfg.SectionEnd+"\n")
	writeUnenrolFile(t, opts.Dir, ".claude/settings.local.json",
		`{"permissions":{"deny":["Read(keep)"]},"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"command":"/usr/local/bin/faramir guard"},{"command":"/opt/user-hook"}]}]}}`)
	writeUnenrolFile(t, opts.Dir, agentcfg.CodexHooksFile,
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"command":"/usr/local/bin/faramir guard --host codex"}]}]}}`)
	if recorded {
		for _, tree := range []agentcfg.EnrolledTree{
			{Dir: opts.Dir, AgentUser: opts.AgentUser, Agents: []string{"claude", "codex", "pi"}},
			{Dir: filepath.Join(t.TempDir(), "other"), AgentUser: opts.AgentUser, Agents: []string{"pi"}},
		} {
			if err := agentcfg.RecordEnrolment(opts.ConfigDir, tree); err != nil {
				t.Fatal(err)
			}
		}
	}
	return opts
}

func writeUnenrolFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func readUnenrolFile(t *testing.T, dir, rel string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestUnenrolTreePreservesSharingAndOtherTrees(t *testing.T) {
	opts := unenrolFixture(t, true)
	before, err := os.Stat(opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := unenrolTree(opts)
	if err != nil || !report.Changed {
		t.Fatalf("unenrol = %+v, %v", report, err)
	}
	for _, rel := range []string{agentcfg.ProjectInstructions, ".claude/settings.local.json", agentcfg.CodexHooksFile} {
		body := readUnenrolFile(t, opts.Dir, rel)
		if bytes.Contains(body, []byte("faramir")) {
			t.Errorf("managed content remains in %s: %s", rel, body)
		}
	}
	body := readUnenrolFile(t, opts.Dir, ".claude/settings.local.json")
	if !bytes.Contains(body, []byte("Read(keep)")) || !bytes.Contains(body, []byte("/opt/user-hook")) {
		t.Fatalf("lost user configuration: %s", body)
	}
	if body := readUnenrolFile(t, opts.Dir, agentcfg.ProjectInstructions); string(body) != "# Project\n\nUser prose.\n\n\n" {
		t.Fatalf("outside prose changed: %q", body)
	}
	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	if err != nil || len(trees) != 1 || trees[0].Dir == opts.Dir {
		t.Fatalf("other record lost: %+v, %v", trees, err)
	}
	after, err := os.Stat(opts.Dir)
	if err != nil || before.Mode() != after.Mode() {
		t.Fatalf("sharing changed: %v", err)
	}
	second, err := unenrolTree(opts)
	if err != nil || second.Changed {
		t.Fatalf("retry changed files: %+v, %v", second, err)
	}
}

func TestUnenrolRefusesNonRootBeforeMutation(t *testing.T) {
	opts := unenrolFixture(t, true)
	before := readUnenrolFile(t, opts.Dir, ".claude/settings.local.json")
	record := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
	if _, err := Unenrol(opts); err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("non-root unenrol accepted: %v", err)
	}
	if !bytes.Equal(before, readUnenrolFile(t, opts.Dir, ".claude/settings.local.json")) ||
		!bytes.Equal(record, readUnenrolFile(t, opts.ConfigDir, "enrolled.json")) {
		t.Fatal("non-root refusal changed files")
	}
}

func TestUnenrolTreeDryRunAndPreflightFailuresWriteNothing(t *testing.T) {
	for _, failure := range []string{"dry run", "bad JSON", "bad markers", "bad record", "escaping symlink", "legacy markers"} {
		t.Run(failure, func(t *testing.T) {
			opts := unenrolFixture(t, true)
			switch failure {
			case "dry run":
				opts.DryRun = true
			case "bad JSON":
				writeUnenrolFile(t, opts.Dir, agentcfg.CodexHooksFile, "{")
			case "bad markers":
				writeUnenrolFile(t, opts.Dir, agentcfg.ProjectInstructions, agentcfg.SectionBegin)
			case "bad record":
				writeUnenrolFile(t, opts.ConfigDir, "enrolled.json", "{")
			case "escaping symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(opts.Dir, ".agents")); err != nil {
					t.Fatal(err)
				}
				writeUnenrolFile(t, opts.Dir, ".agents/rules/faramir.md", "legacy")
			case "legacy markers":
				writeUnenrolFile(t, opts.Dir, "CLAUDE.md", agentcfg.SectionEnd)
			}
			before := readUnenrolFile(t, opts.Dir, ".claude/settings.local.json")
			record := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
			_, err := unenrolTree(opts)
			if (failure == "dry run") != (err == nil) {
				t.Fatalf("unexpected result: %v", err)
			}
			if !bytes.Equal(before, readUnenrolFile(t, opts.Dir, ".claude/settings.local.json")) ||
				!bytes.Equal(record, readUnenrolFile(t, opts.ConfigDir, "enrolled.json")) {
				t.Fatal("preflight or dry run wrote files")
			}
		})
	}
}

func TestUnenrolTreeChecksConcurrentRecordChangesWithAndWithoutRecord(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "recorded"}[recorded], func(t *testing.T) {
			opts := unenrolFixture(t, recorded)
			updated := false
			opts.Log = func(line string) {
				if updated {
					return
				}
				updated = true
				if err := agentcfg.RecordEnrolment(opts.ConfigDir, agentcfg.EnrolledTree{
					Dir: opts.Dir, AgentUser: opts.AgentUser, Agents: []string{"pi", "opencode"},
				}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := unenrolTree(opts)
			if err == nil || !strings.Contains(err.Error(), "record") {
				t.Fatalf("concurrent record update accepted: %v", err)
			}
			found := false
			for _, tree := range agentcfg.ReadEnrolled(opts.ConfigDir) {
				if tree.Dir == opts.Dir && strings.Contains(strings.Join(tree.Agents, ","), "opencode") {
					found = true
				}
			}
			if !found {
				t.Fatal("concurrent record update lost")
			}
		})
	}
}

func TestUnenrolTreeUnrecordedCleanupReportsLegacyText(t *testing.T) {
	opts := unenrolFixture(t, false)
	legacy := agentcfg.SectionBegin + "\nold text\n" + agentcfg.SectionEnd
	writeUnenrolFile(t, opts.Dir, "CLAUDE.md", legacy)
	report, err := unenrolTree(opts)
	if err != nil || !report.Changed {
		t.Fatalf("unrecorded cleanup failed: %+v, %v", report, err)
	}
	if !strings.Contains(strings.Join(report.Warnings, "\n"), "legacy project instructions") {
		t.Fatal("legacy managed text was not reported")
	}
	if body := readUnenrolFile(t, opts.Dir, "CLAUDE.md"); string(body) != legacy {
		t.Fatal("legacy instructions changed")
	}
	if _, err := os.Stat(agentcfg.EnrolledPath(opts.ConfigDir)); !os.IsNotExist(err) {
		t.Fatal("unrecorded cleanup created a record")
	}
}

func TestUnenrolTreeRefusesConcurrentProjectEdits(t *testing.T) {
	opts := unenrolFixture(t, true)
	updated := false
	opts.Log = func(line string) {
		if !updated {
			updated = true
			writeUnenrolFile(t, opts.Dir, agentcfg.CodexHooksFile, `{"operator":"concurrent edit"}`)
		}
	}
	if _, err := unenrolTree(opts); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("concurrent project edit accepted: %v", err)
	}
	if body := readUnenrolFile(t, opts.Dir, agentcfg.CodexHooksFile); string(body) != `{"operator":"concurrent edit"}` {
		t.Fatalf("concurrent project edit lost: %s", body)
	}
	found := false
	for _, tree := range agentcfg.ReadEnrolled(opts.ConfigDir) {
		found = found || tree.Dir == opts.Dir
	}
	if !found {
		t.Fatal("record removed after partial cleanup failure")
	}
}

func TestUnenrolTreeCleansSharedInstructionAliasOnce(t *testing.T) {
	opts := unenrolFixture(t, true)
	if err := os.Symlink(agentcfg.ProjectInstructions, filepath.Join(opts.Dir, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	report, err := unenrolTree(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range report.Warnings {
		if strings.Contains(warning, "legacy project instructions") {
			t.Fatal("shared physical section reported as remaining legacy text")
		}
	}
	if body := readUnenrolFile(t, opts.Dir, "CLAUDE.md"); bytes.Contains(body, []byte(agentcfg.SectionBegin)) {
		t.Fatal("alias retains managed block")
	}
}
