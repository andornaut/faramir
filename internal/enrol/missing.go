package enrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/steps"
)

// Resolve existing components before treating ENOENT as absence. A symlink
// whose target is missing is an unresolved path, not a missing project.
func resolveUnenrolPath(named string) (string, bool, error) {
	abs, err := filepath.Abs(named)
	if err != nil {
		return "", false, err
	}
	parts := strings.Split(strings.TrimPrefix(abs, string(os.PathSeparator)), string(os.PathSeparator))
	current := string(os.PathSeparator)
	for i, part := range parts {
		if part == "" {
			continue
		}
		path := filepath.Join(current, part)
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return filepath.Join(append([]string{path}, parts[i+1:]...)...), true, nil
		case err != nil:
			return "", false, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				return "", false, fmt.Errorf("cannot resolve symlink %s: %w", filepath.Join(current, part), err)
			}
			info, err = os.Stat(path)
			if err != nil {
				return "", false, err
			}
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", false, fmt.Errorf("%s is not a directory", path)
		}
		current = path
	}
	return current, false, nil
}

func forgetMissingRecords(opts UnenrolOptions, report UnenrolReport) (UnenrolReport, error) {
	report.RecordOnly = true
	if opts.ConfigDir == "" {
		opts.ConfigDir = hostlayout.DefaultConfigDir
	}
	if err := refuseUnenrolAgent(opts.AgentUser); err != nil {
		return report, err
	}
	if !opts.Missing {
		if err := refuseMissingScope(opts, report.Dir); err != nil {
			return report, err
		}
	}
	state, err := snapshotUnenrolRecord(opts.ConfigDir)
	if err != nil {
		return report, err
	}
	missing, remaining, err := selectMissingRecords(opts, state)
	if err != nil {
		return report, err
	}
	report.MissingRecords = missing
	for _, dir := range missing {
		report.Record("missing enrolment", false, dir)
	}
	// Absence can change independently of the record. Check again immediately
	// before its CAS write; no atomicity with outside filesystem changes is claimed.
	for _, dir := range missing {
		_, absent, err := resolveUnenrolPath(dir)
		if err != nil {
			return report, err
		}
		if !absent {
			return report, fmt.Errorf("%s exists again; nothing was written", dir)
		}
	}
	if err := checkUnenrolRecord(opts.ConfigDir, state); err != nil {
		return report, err
	}
	if len(missing) == 0 {
		report.Record(steps.LabelEnrolledTrees, false, "no matching missing enrolment records")
		return report, nil
	}
	body, err := json.MarshalIndent(remaining, "", "  ")
	if err != nil {
		return report, err
	}
	changed, err := (hostfs.FS{DryRun: opts.DryRun}).WriteFileExpecting(
		agentcfg.EnrolledPath(opts.ConfigDir), append(body, '\n'), 0o600, state.digest)
	if err != nil {
		return report, fmt.Errorf("missing enrolment records were not removed: %w", err)
	}
	report.Record(steps.LabelEnrolledTrees, changed, strings.Join(missing, ", "))
	return report, nil
}

func selectMissingRecords(opts UnenrolOptions, state unenrolRecord) ([]string, []json.RawMessage, error) {
	missing := []string{}
	remaining := make([]json.RawMessage, 0, len(state.entries))
	for i, tree := range state.trees {
		if tree.Dir == "" || !filepath.IsAbs(tree.Dir) || filepath.Clean(tree.Dir) != tree.Dir {
			return nil, nil, fmt.Errorf("%s holds an empty, relative or unclean directory; nothing was written\n"+
				"  repair that entry, then run this again", agentcfg.EnrolledPath(opts.ConfigDir))
		}
		if !opts.Missing && tree.Dir != opts.Dir {
			remaining = append(remaining, state.entries[i])
			continue
		}
		dir, absent, err := resolveUnenrolPath(tree.Dir)
		if err != nil {
			return nil, nil, err
		}
		if !absent {
			if !opts.Missing {
				return nil, nil, fmt.Errorf("%s exists again; nothing was written", tree.Dir)
			}
			remaining = append(remaining, state.entries[i])
			continue
		}
		if err := refuseMissingScope(opts, dir); err != nil {
			return nil, nil, err
		}
		missing = append(missing, tree.Dir)
	}
	sort.Strings(missing)
	return slices.Compact(missing), remaining, nil
}

func refuseMissingScope(opts UnenrolOptions, dir string) error {
	if err := RefuseOversharing(dir, opts.AgentUser); err != nil {
		return err
	}
	return RefuseInstallDirs(dir, opts.ConfigDir)
}
