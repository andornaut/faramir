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
	Log       func(string)
}

// UnenrolReport includes retained protections and access in Warnings.
type UnenrolReport struct {
	steps.Report

	Version string `json:"version"`
	Dir     string `json:"dir"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

// Unenrol removes project routing, the marked project section and the record
// that init maintains. It cannot reconstruct permissions preceding enrolment.
func Unenrol(opts UnenrolOptions) (UnenrolReport, error) {
	if os.Geteuid() != 0 && !opts.DryRun {
		return UnenrolReport{}, errors.New("faramir unenrol must run as root")
	}
	return unenrolTree(opts)
}

type unenrolEdit struct {
	spot   *hostfs.Edited
	before []byte
	after  []byte
}

func unenrolTree(opts UnenrolOptions) (UnenrolReport, error) {
	report := UnenrolReport{Version: version.Version, DryRun: opts.DryRun}
	report.LogTo(opts.Log)
	opts, dir, uid, err := resolveUnenrol(&report, opts)
	if err != nil {
		return report, err
	}
	record, err := readUnenrolRecord(opts, dir)
	if err != nil {
		return report, err
	}
	if !record.recorded {
		report.Warnf("no enrolment record for %s; checking known project routing files and the marked project section", dir)
	}
	edits, seen, err := prepareUnenrolEdits(uid, dir)
	if err != nil {
		return report, err
	}
	defer closeUnenrolEdits(edits)
	if err := checkUnenrolLegacy(&report, seen, uid, dir); err != nil {
		return report, err
	}
	report.Warnf("retained project permission rules, global hooks, global deny rules and global instructions")
	report.Warnf("retained filesystem sharing: ownership, groups, modes, setgid/sticky bits and traversal grants; unenrolment does not revoke broker access")
	report.Warnf("start fresh agent sessions after unenrolment; loaded sessions may retain project hooks and instructions")
	fs := hostfs.FS{DryRun: opts.DryRun}
	if err := applyUnenrolEdits(fs, &report, edits); err != nil {
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
	if opts.AgentUser == "" || opts.AgentUser == "root" {
		return opts, "", 0, errors.New("no agent account: run through sudo, or set --agent-user on init (not root)")
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

type unenrolRecord struct {
	body     []byte
	digest   []byte
	trees    []agentcfg.EnrolledTree
	recorded bool
}

func readUnenrolRecord(opts UnenrolOptions, dir string) (unenrolRecord, error) {
	// Snapshot before parsing. The final compare rejects a record changed at
	// any point during preflight or cleanup, preserving other trees' entries.
	record, err := os.ReadFile(agentcfg.EnrolledPath(opts.ConfigDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return unenrolRecord{}, err
	}
	var digest []byte
	if err == nil {
		sum := sha256.Sum256(record)
		digest = sum[:]
	}
	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	if err != nil {
		return unenrolRecord{}, err
	}
	recorded := false
	for _, tree := range trees {
		if tree.Dir != dir {
			continue
		}
		recorded = true
		if tree.AgentUser != opts.AgentUser {
			return unenrolRecord{}, fmt.Errorf("%s was enrolled for %s, not %s", dir, tree.AgentUser, opts.AgentUser)
		}
		for _, name := range tree.Agents {
			if agentcfg.Targets[name] == nil {
				return unenrolRecord{}, fmt.Errorf("%s records unknown agent %q; repair the enrolment record first", dir, name)
			}
		}
	}
	return unenrolRecord{body: record, digest: digest, trees: trees, recorded: recorded}, nil
}

func closeUnenrolEdits(edits []unenrolEdit) {
	for _, edit := range edits {
		edit.spot.Close()
	}
}

func prepareUnenrolEdits(uid int, dir string) (_ []unenrolEdit, _ map[string]bool, err error) {
	var edits []unenrolEdit
	defer func() {
		if err != nil {
			closeUnenrolEdits(edits)
		}
	}()
	// Inspect every current project file even without a record: an enrolment
	// may have written routing and failed before recording it.
	paths := []string{agentcfg.ProjectInstructions}
	for _, target := range agentcfg.Targets {
		for _, file := range target.Files {
			if !file.Merge {
				return nil, nil, fmt.Errorf("no safe cleanup contract for %s", file.Path)
			}
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	paths = slices.Compact(paths)
	seen := map[string]bool{}
	for _, rel := range paths {
		spot, err := (hostfs.FS{}).EditedFile(filepath.Join(dir, rel), uid, dir)
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
		if rel == agentcfg.ProjectInstructions {
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
			report.Warnf("legacy project instructions at %s retain faramir credentials text; review and remove obsolete text manually", path)
		}
	}
	return nil
}

func applyUnenrolEdits(fs hostfs.FS, report *UnenrolReport, edits []unenrolEdit) error {
	for _, edit := range edits {
		if bytes.Equal(edit.before, edit.after) {
			report.Record("project configuration", false, edit.spot.Path())
			continue
		}
		owner, group := hostfs.OwnerOf(edit.spot.Info())
		sum := sha256.Sum256(edit.before)
		changed, err := fs.WriteEditedExpecting(edit.spot, edit.after, edit.spot.Info().Mode().Perm(), owner, group, sum[:])
		if err != nil {
			return fmt.Errorf("project cleanup stopped; earlier changes may have applied, retry after resolving the error: %w", err)
		}
		report.Record("project configuration", changed, edit.spot.Path())
	}
	return nil
}

func finishUnenrolRecord(fs hostfs.FS, report *UnenrolReport, configDir, dir string, state unenrolRecord) error {
	recorded, trees, digest, record := state.recorded, state.trees, state.digest, state.body
	if recorded {
		remaining := slices.DeleteFunc(trees, func(tree agentcfg.EnrolledTree) bool { return tree.Dir == dir })
		if remaining == nil {
			remaining = []agentcfg.EnrolledTree{}
		}
		body, err := json.MarshalIndent(remaining, "", "  ")
		if err != nil {
			return err
		}
		changed, err := fs.WriteFileExpecting(agentcfg.EnrolledPath(configDir), append(body, '\n'), 0o600, digest)
		if err != nil {
			return fmt.Errorf("project configuration cleaned, but the enrolment record was not updated; retry before running init: %w", err)
		}
		report.Record(steps.LabelEnrolledTrees, changed, dir)
	} else {
		current, readErr := os.ReadFile(agentcfg.EnrolledPath(configDir))
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if (digest == nil) != errors.Is(readErr, os.ErrNotExist) || !bytes.Equal(current, record) {
			return errors.New("enrolment record changed during cleanup; retry before running init")
		}
		report.Record(steps.LabelEnrolledTrees, false, dir)
	}
	return nil
}
