package enrol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

func missingFixture(t *testing.T) (UnenrolOptions, string, string) {
	t.Helper()
	opts := unenrolFixture(t, false)
	live := opts.Dir
	missing := filepath.Join(t.TempDir(), "gone")
	opts.Dir, opts.Missing = "", true
	writeMissingRecords(t, opts.ConfigDir, []agentcfg.EnrolledTree{
		{Dir: missing, AgentUser: "former-unknown-account", Agents: []string{"retired-harness"}},
		{Dir: live, AgentUser: opts.AgentUser, Agents: []string{"claude", "codex"}},
	})
	return opts, missing, live
}

func writeMissingRecords(t *testing.T, configDir string, trees []agentcfg.EnrolledTree) {
	t.Helper()
	body, err := json.MarshalIndent(trees, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentcfg.EnrolledPath(configDir), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUnenrolMissingBulkPreservesExistingProjectsAndRecordFields(t *testing.T) {
	opts, missing, live := missingFixture(t)
	second := filepath.Join(t.TempDir(), "also-gone")
	entries := []map[string]any{
		{"dir": missing, "agent_user": "former-account", "agents": []string{"unknown"}},
		{"dir": live, "agent_user": opts.AgentUser, "agents": []string{"claude"}, "future": json.Number("9007199254740993")},
		{"dir": second, "agent_user": opts.AgentUser, "agents": []string{"codex"}},
	}
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	writeUnenrolFile(t, opts.ConfigDir, "enrolled.json", string(body))
	projectBefore := readUnenrolFile(t, live, ".claude/settings.local.json")
	report, err := unenrolTree(opts)
	if err != nil || !report.Changed || !report.Bulk || !report.RecordOnly || len(report.MissingRecords) != 2 {
		t.Fatalf("bulk cleanup: %+v, %v", report, err)
	}
	if !bytes.Equal(projectBefore, readUnenrolFile(t, live, ".claude/settings.local.json")) {
		t.Fatal("bulk cleanup edited an existing project's routing")
	}
	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	if err != nil || len(trees) != 1 || trees[0].Dir != live {
		t.Fatalf("existing record was not preserved: %+v, %v", trees, err)
	}
	if !bytes.Contains(readUnenrolFile(t, opts.ConfigDir, "enrolled.json"), []byte("9007199254740993")) {
		t.Fatal("unrecognized surviving record fields were lost or rounded")
	}
	secondReport, err := unenrolTree(opts)
	if err != nil || secondReport.Changed || len(secondReport.MissingRecords) != 0 {
		t.Fatalf("repeated bulk cleanup changed records: %+v, %v", secondReport, err)
	}
}

func TestUnenrolMissingExplicitPathResolvesRelativeSymlinkAncestor(t *testing.T) {
	opts, _, live := missingFixture(t)
	realDir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(realDir, "gone", "nested")
	writeMissingRecords(t, opts.ConfigDir, []agentcfg.EnrolledTree{
		{Dir: missing, AgentUser: "former-account", Agents: []string{"unknown"}},
		{Dir: live, AgentUser: opts.AgentUser, Agents: []string{"claude"}},
	})
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	opts.Dir, err = filepath.Rel(cwd, filepath.Join(alias, "gone", "nested"))
	if err != nil {
		t.Fatal(err)
	}
	opts.Missing = false
	report, err := unenrolTree(opts)
	if err != nil || !report.Changed || report.Bulk || report.Dir != missing || !slices.Equal(report.MissingRecords, []string{missing}) {
		t.Fatalf("explicit missing cleanup: %+v, %v", report, err)
	}
	if trees := agentcfg.ReadEnrolled(opts.ConfigDir); len(trees) != 1 || trees[0].Dir != live {
		t.Fatal("explicit cleanup removed an unrelated record")
	}
}

func TestUnenrolMissingDryRunNoMatchAndAbsentRecord(t *testing.T) {
	opts, missing, _ := missingFixture(t)
	before := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
	opts.DryRun = true
	report, err := unenrolTree(opts)
	if err != nil || !report.Changed || !report.DryRun || len(report.MissingRecords) != 1 {
		t.Fatalf("bulk dry run: %+v, %v", report, err)
	}
	if !bytes.Equal(before, readUnenrolFile(t, opts.ConfigDir, "enrolled.json")) {
		t.Fatal("dry run changed the record")
	}
	opts.Missing, opts.Dir = false, missing+"-unrecorded"
	report, err = unenrolTree(opts)
	if err != nil || report.Changed || !report.RecordOnly || report.Dir != opts.Dir {
		t.Fatalf("unrecorded missing path: %+v, %v", report, err)
	}
	opts.Missing, opts.Dir, opts.ConfigDir = true, "", t.TempDir()
	report, err = unenrolTree(opts)
	if err != nil || report.Changed || !report.Bulk || len(report.MissingRecords) != 0 {
		t.Fatalf("absent record: %+v, %v", report, err)
	}
	if _, err := os.Lstat(agentcfg.EnrolledPath(opts.ConfigDir)); !os.IsNotExist(err) {
		t.Fatal("empty cleanup created an enrolment record")
	}
}

func TestUnenrolMissingRejectsScanErrorsBeforeAnyRecordWrite(t *testing.T) {
	for _, problem := range []string{"permission", "dangling ancestor", "non-directory ancestor", "bad JSON", "null", "bad entry"} {
		t.Run(problem, func(t *testing.T) {
			opts, missing, live := missingFixture(t)
			bad := filepath.Join(t.TempDir(), "bad")
			switch problem {
			case "permission":
				if err := os.Mkdir(bad, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(bad, 0); err != nil {
					t.Fatal(err)
				}
				blocked := bad
				defer func() { _ = os.Chmod(blocked, 0o700) }()
				bad = filepath.Join(bad, "unknown")
			case "dangling ancestor":
				if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), bad); err != nil {
					t.Fatal(err)
				}
				bad = filepath.Join(bad, "child")
			case "non-directory ancestor":
				if err := os.WriteFile(bad, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				bad = filepath.Join(bad, "child")
			}
			writeMissingRecords(t, opts.ConfigDir, []agentcfg.EnrolledTree{
				{Dir: missing, AgentUser: opts.AgentUser},
				{Dir: bad, AgentUser: opts.AgentUser},
				{Dir: live, AgentUser: opts.AgentUser},
			})
			switch problem {
			case "bad JSON":
				writeUnenrolFile(t, opts.ConfigDir, "enrolled.json", "{")
			case "null":
				writeUnenrolFile(t, opts.ConfigDir, "enrolled.json", "null")
			case "bad entry":
				writeUnenrolFile(t, opts.ConfigDir, "enrolled.json", "[{}]")
			}
			before := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
			report, err := unenrolTree(opts)
			if err == nil || report.Changed {
				t.Fatalf("uncertain scan was accepted: %+v, %v", report, err)
			}
			if !bytes.Equal(before, readUnenrolFile(t, opts.ConfigDir, "enrolled.json")) {
				t.Fatal("scan error rewrote the record")
			}
		})
	}
}

func TestUnenrolMissingRefusesReappearanceAndConcurrentRecordUpdate(t *testing.T) {
	for _, update := range []string{"directory", "record"} {
		t.Run(update, func(t *testing.T) {
			opts, missing, live := missingFixture(t)
			before := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
			called := false
			opts.Log = func(line string) {
				if called || !strings.Contains(line, "missing enrolment") {
					return
				}
				called = true
				if update == "directory" {
					if err := os.Mkdir(missing, 0o700); err != nil {
						t.Fatal(err)
					}
				} else {
					writeMissingRecords(t, opts.ConfigDir, []agentcfg.EnrolledTree{{Dir: live, AgentUser: opts.AgentUser}})
					before = readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
				}
			}
			report, err := unenrolTree(opts)
			if !called || err == nil || report.Changed {
				t.Fatalf("concurrent change accepted: %+v, %v", report, err)
			}
			if !bytes.Equal(before, readUnenrolFile(t, opts.ConfigDir, "enrolled.json")) {
				t.Fatal("concurrent state was overwritten")
			}
		})
	}
}

func TestUnenrolMissingRejectsUnsafeScopesAndDirectoryArgument(t *testing.T) {
	opts, _, _ := missingFixture(t)
	before := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
	opts.Dir = filepath.Join(t.TempDir(), "gone")
	if _, err := unenrolTree(opts); err == nil {
		t.Fatal("bulk cleanup accepted a directory")
	}
	opts.Missing = false
	opts.Dir = filepath.Join(opts.ConfigDir, "gone")
	if _, err := unenrolTree(opts); err == nil {
		t.Fatal("record-only cleanup accepted an install directory")
	}
	if !bytes.Equal(before, readUnenrolFile(t, opts.ConfigDir, "enrolled.json")) {
		t.Fatal("unsafe scope changed records")
	}
}

func TestUnenrolExistingTreePreservesUnknownSurvivingRecordFields(t *testing.T) {
	opts := unenrolFixture(t, true)
	var entries []map[string]json.RawMessage
	body := readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		entry["future"] = json.RawMessage(`{"ordinal":9007199254740993}`)
	}
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	writeUnenrolFile(t, opts.ConfigDir, "enrolled.json", string(body))
	if _, err := unenrolTree(opts); err != nil {
		t.Fatal(err)
	}
	body = readUnenrolFile(t, opts.ConfigDir, "enrolled.json")
	if !bytes.Contains(body, []byte(`"future"`)) || !bytes.Contains(body, []byte("9007199254740993")) {
		t.Fatal("ordinary cleanup dropped or rounded surviving record fields")
	}
}
