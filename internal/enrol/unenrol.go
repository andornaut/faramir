package enrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/sharetree"
	"github.com/andornaut/faramir/internal/steps"
	"github.com/andornaut/faramir/internal/version"
)

// UnenrolOptions removes one project's routing and maintenance registration.
type UnenrolOptions struct {
	Dir       string
	AgentUser string
	ConfigDir string
	DryRun    bool
	Missing   bool
	Log       func(string)
}

// UnenrolReport includes retained protections and access in Warnings.
type UnenrolReport struct {
	steps.Report

	Version        string   `json:"version"`
	Dir            string   `json:"dir"`
	DryRun         bool     `json:"dry_run,omitempty"`
	Bulk           bool     `json:"bulk,omitempty"`
	RecordOnly     bool     `json:"record_only,omitempty"`
	MissingRecords []string `json:"missing_records,omitempty"`
}

// Unenrol removes project routing, the marked project section and the record
// that init maintains. It cannot reconstruct permissions preceding enrolment.
func Unenrol(opts UnenrolOptions) (UnenrolReport, error) {
	if os.Geteuid() != 0 && !opts.DryRun {
		return UnenrolReport{}, errors.New("must run as root")
	}
	return unenrolTree(opts)
}

type unenrolEdit struct {
	spot   *hostfs.Edited
	before []byte
	after  []byte
}

func unenrolTree(opts UnenrolOptions) (UnenrolReport, error) {
	report := UnenrolReport{Version: version.Version, DryRun: opts.DryRun, Bulk: opts.Missing}
	report.LogTo(opts.Log)
	if opts.Missing {
		if opts.Dir != "" {
			return report, errors.New("--missing cannot be combined with a directory")
		}
		return forgetMissingRecords(opts, report)
	}
	if opts.Dir != "" {
		dir, missing, err := resolveUnenrolPath(opts.Dir)
		if err != nil {
			return report, err
		}
		opts.Dir = dir
		if missing {
			report.Dir = dir
			return forgetMissingRecords(opts, report)
		}
	}
	opts, dir, uid, err := resolveUnenrol(&report, opts)
	if err != nil {
		return report, err
	}
	record, err := readUnenrolRecord(opts, dir)
	if err != nil {
		return report, err
	}
	if !record.recorded {
		report.Warnf("no enrolment record for %s; cleaning the known project files anyway", dir)
	}
	files, err := treeUnenrolFiles()
	if err != nil {
		return report, err
	}
	edits, seen, err := prepareUnenrolEdits(uid, dir, dir, files)
	if err != nil {
		return report, err
	}
	defer closeUnenrolEdits(edits)
	if err := checkUnenrolLegacy(&report, seen, uid, dir); err != nil {
		return report, err
	}
	report.Warnf("filesystem sharing is kept: brokered commands can still reach %s\n"+
		"  restart agent sessions running there", dir)
	fs := hostfs.FS{DryRun: opts.DryRun}
	if err := applyUnenrolEdits(fs, &report, "project configuration", edits); err != nil {
		return report, err
	}
	if err := finishUnenrolRecord(fs, &report, opts.ConfigDir, dir, record); err != nil {
		return report, err
	}
	return report, nil
}

func resolveUnenrol(report *UnenrolReport, opts UnenrolOptions) (UnenrolOptions, string, int, error) {
	if opts.Dir == "" {
		var err error
		opts.Dir, err = os.Getwd()
		if err != nil {
			return opts, "", 0, err
		}
	}
	dir, err := sharetree.Resolve(opts.Dir)
	if err != nil {
		return opts, "", 0, err
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return opts, "", 0, fmt.Errorf("no directory at %s", dir)
	}
	report.Dir = dir
	if opts.ConfigDir == "" {
		opts.ConfigDir = hostlayout.DefaultConfigDir
	}
	if err := refuseUnenrolAgent(opts.AgentUser); err != nil {
		return opts, "", 0, err
	}
	if err := RefuseOversharing(dir, opts.AgentUser); err != nil {
		return opts, "", 0, err
	}
	if err := RefuseInstallDirs(dir, opts.ConfigDir); err != nil {
		return opts, "", 0, err
	}
	uid, err := hostfs.LookupUser(opts.AgentUser)
	if err != nil {
		return opts, "", 0, err
	}
	return opts, dir, uid, nil
}

func refuseUnenrolAgent(name string) error {
	if name == "" || name == "root" {
		return errors.New("no agent account\n  run through sudo, or pass --agent-user (not root) to init")
	}
	return nil
}

type unenrolRecord struct {
	body     []byte
	digest   []byte
	trees    []agentcfg.EnrolledTree
	entries  []json.RawMessage
	recorded bool
}

func readUnenrolRecord(opts UnenrolOptions, dir string) (unenrolRecord, error) {
	state, err := snapshotUnenrolRecord(opts.ConfigDir)
	if err != nil {
		return state, err
	}
	for _, tree := range state.trees {
		if tree.Dir != dir {
			continue
		}
		state.recorded = true
		if tree.AgentUser != opts.AgentUser {
			return unenrolRecord{}, fmt.Errorf("%s was enrolled for %s, not %s", dir, tree.AgentUser, opts.AgentUser)
		}
		for _, name := range tree.Agents {
			if agentcfg.Targets[name] == nil {
				return unenrolRecord{}, fmt.Errorf("%s: enrolment record names unknown agent %q\n  repair %s first",
					dir, name, agentcfg.EnrolledPath(opts.ConfigDir))
			}
		}
	}
	return state, nil
}

func snapshotUnenrolRecord(configDir string) (unenrolRecord, error) {
	// Snapshot before parsing. The final compare rejects a record changed at
	// any point during preflight or cleanup, preserving other trees' entries.
	record, err := os.ReadFile(agentcfg.EnrolledPath(configDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return unenrolRecord{}, err
	}
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(agentcfg.EnrolledPath(configDir)); statErr == nil {
			return unenrolRecord{}, fmt.Errorf("%s is a dangling symlink", agentcfg.EnrolledPath(configDir))
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return unenrolRecord{}, statErr
		}
	}
	var digest []byte
	if err == nil {
		sum := sha256.Sum256(record)
		digest = sum[:]
	}
	state := unenrolRecord{body: record, digest: digest}
	if digest == nil {
		return state, nil
	}
	if bytes.Equal(bytes.TrimSpace(record), []byte("null")) {
		return state, fmt.Errorf("%s must contain an array of enrolment records", agentcfg.EnrolledPath(configDir))
	}
	if err := json.Unmarshal(record, &state.entries); err != nil {
		return state, fmt.Errorf("%s: %w", agentcfg.EnrolledPath(configDir), err)
	}
	for _, entry := range state.entries {
		var tree agentcfg.EnrolledTree
		if err := json.Unmarshal(entry, &tree); err != nil {
			return state, fmt.Errorf("%s: %w", agentcfg.EnrolledPath(configDir), err)
		}
		state.trees = append(state.trees, tree)
	}
	return state, nil
}

func closeUnenrolEdits(edits []unenrolEdit) {
	for _, edit := range edits {
		edit.spot.Close()
	}
}

// unenrolFile is one file an unenrolment edits, relative to the tree or home it
// cleans: either the marked credentials section or the merged hooks.
type unenrolFile struct {
	rel     string
	section bool
}

// treeUnenrolFiles is every project file any agent's enrolment writes. Every
// one is inspected even without a record: an enrolment may have written
// routing and failed before recording it.
func treeUnenrolFiles() ([]unenrolFile, error) {
	paths := []string{agentcfg.ProjectInstructions}
	for _, target := range agentcfg.Targets {
		for _, file := range target.Files {
			if !file.Merge {
				return nil, fmt.Errorf("no safe cleanup contract for %s", file.Path)
			}
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	paths = slices.Compact(paths)
	files := make([]unenrolFile, 0, len(paths))
	for _, rel := range paths {
		files = append(files, unenrolFile{rel: rel, section: rel == agentcfg.ProjectInstructions})
	}
	return files, nil
}

// prepareUnenrolEdits reads and strips each file under dir before anything is
// written. within bounds where a followed link may land, empty in a home as
// for `init`'s own writes there.
func prepareUnenrolEdits(uid int, dir, within string, files []unenrolFile) (_ []unenrolEdit, _ map[string]bool, err error) {
	var edits []unenrolEdit
	defer func() {
		if err != nil {
			closeUnenrolEdits(edits)
		}
	}()
	seen := map[string]bool{}
	for _, file := range files {
		rel := file.rel
		spot, err := (hostfs.FS{}).EditedFile(filepath.Join(dir, rel), uid, within)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", rel, err)
		}
		if spot.Info() == nil {
			spot.Close()
			continue
		}
		if seen[spot.Path()] {
			spot.Close()
			return nil, nil, fmt.Errorf("%s aliases another project configuration file", rel)
		}
		seen[spot.Path()] = true
		before, err := spot.Read()
		if err != nil {
			spot.Close()
			return nil, nil, err
		}
		var after []byte
		if file.section {
			after, err = agentcfg.WithoutProjectSection(before)
		} else {
			after, err = agentcfg.WithoutProjectConfig(before)
		}
		if err != nil {
			spot.Close()
			return nil, nil, fmt.Errorf("%s: %w", rel, err)
		}
		edits = append(edits, unenrolEdit{spot: spot, before: before, after: after})
	}
	return edits, seen, nil
}

// CLEANUP (added 2026-10-31): the legacy instruction-file migration. Remove
// once every enrolled tree has been re-enrolled once on a release that carries
// the migration.
func checkUnenrolLegacy(report *UnenrolReport, seen map[string]bool, uid int, dir string) error {
	// Legacy instruction files are retained. An alias of the shared file is
	// covered by that one edit; an independent managed block needs attention.
	for _, rel := range []string{"CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".claude/CLAUDE.md", ".agents/rules/faramir.md"} {
		path := filepath.Join(dir, rel)
		spot, err := (hostfs.FS{}).EditedFile(path, uid, dir)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if spot.Info() == nil || seen[spot.Path()] {
			spot.Close()
			continue
		}
		body, err := spot.Read()
		spot.Close()
		if err != nil {
			return err
		}
		after, sectionErr := agentcfg.WithoutProjectSection(body)
		marked := bytes.Contains(body, []byte(agentcfg.SectionBegin)) || bytes.Contains(body, []byte(agentcfg.SectionEnd))
		if sectionErr != nil && marked {
			return fmt.Errorf("%s: %w", rel, sectionErr)
		}
		if sectionErr != nil || !bytes.Equal(body, after) {
			report.Warnf("legacy project instructions at %s still hold faramir credentials text\n  remove it by hand", path)
		}
	}
	return nil
}

func applyUnenrolEdits(fs hostfs.FS, report *UnenrolReport, label string, edits []unenrolEdit) error {
	for _, edit := range edits {
		if bytes.Equal(edit.before, edit.after) {
			report.Record(label, false, edit.spot.Path())
			continue
		}
		owner, group := hostfs.OwnerOf(edit.spot.Info())
		sum := sha256.Sum256(edit.before)
		changed, err := fs.WriteEditedExpecting(edit.spot, edit.after, edit.spot.Info().Mode().Perm(), owner, group, sum[:])
		if err != nil {
			return fmt.Errorf("cleanup stopped, earlier files may already be cleaned: %w", err)
		}
		report.Record(label, changed, edit.spot.Path())
	}
	return nil
}

func finishUnenrolRecord(fs hostfs.FS, report *UnenrolReport, configDir, dir string, state unenrolRecord) error {
	if state.recorded {
		remaining := make([]json.RawMessage, 0, len(state.entries))
		for i, tree := range state.trees {
			if tree.Dir != dir {
				remaining = append(remaining, state.entries[i])
			}
		}
		body, err := json.MarshalIndent(remaining, "", "  ")
		if err != nil {
			return err
		}
		changed, err := fs.WriteFileExpecting(agentcfg.EnrolledPath(configDir), append(body, '\n'), 0o600, state.digest)
		if err != nil {
			return fmt.Errorf("project files cleaned, enrolment record not updated: %w", err)
		}
		report.Record(steps.LabelEnrolledTrees, changed, dir)
	} else {
		if err := checkUnenrolRecord(configDir, state); err != nil {
			return err
		}
		report.Record(steps.LabelEnrolledTrees, false, dir)
	}
	return nil
}

func checkUnenrolRecord(configDir string, state unenrolRecord) error {
	current, err := os.ReadFile(agentcfg.EnrolledPath(configDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if (state.digest == nil) != errors.Is(err, os.ErrNotExist) || !bytes.Equal(current, state.body) {
		return fmt.Errorf("enrolment record %s changed during cleanup\n  run this again before the next init",
			agentcfg.EnrolledPath(configDir))
	}
	return nil
}
