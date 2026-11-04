package enrol

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/version"
)

// UnenrolHome removes what `init` wrote into an agent account's home for every
// agent: the hooks merged into its account files, the plugins and extensions
// that are faramir's own files, and the marked credentials section. Deny rules
// are kept, as Unenrol keeps a tree's permission rules.
//
// Best effort per half: a merged file that cannot be stripped does not keep
// the plugins in place, which fail closed once the binary they exec is gone.
func UnenrolHome(uid int, home string) (UnenrolReport, error) {
	report := UnenrolReport{Version: version.Version, Dir: home}
	edited, owned := homeUnenrolFiles()
	var failures []error
	if err := removeOwnedHomeFiles(&report, uid, home, owned); err != nil {
		failures = append(failures, err)
	}
	edits, _, err := prepareUnenrolEdits(uid, home, "", edited)
	if err == nil {
		err = applyUnenrolEdits(hostfs.FS{}, &report, "agent configuration", edits)
		closeUnenrolEdits(edits)
	}
	if err != nil {
		failures = append(failures, err)
	}
	return report, errors.Join(failures...)
}

// homeUnenrolFiles is every account file and home instructions file any agent
// has, each path once: the files faramir edits, and the ones that are its own.
func homeUnenrolFiles() (edited []unenrolFile, owned []string) {
	byPath := map[string]unenrolFile{}
	for _, target := range agentcfg.Targets {
		for _, file := range target.AccountFiles {
			if !file.Merge {
				owned = append(owned, file.Path)
				continue
			}
			byPath[file.Path] = mergedUnenrolFile(file)
		}
		if target.HomeInstructions != "" {
			byPath[target.HomeInstructions] = unenrolFile{rel: target.HomeInstructions,
				without: agentcfg.WithoutProjectSection, owned: target.OwnsHomeInstructions}
		}
	}
	sort.Strings(owned)
	return sortedUnenrolFiles(byPath), slices.Compact(owned)
}

// removeOwnedHomeFiles removes each of faramir's own files that is the
// operator's: a link is removed rather than what it names, and a file somebody
// else owns is reported rather than removed.
func removeOwnedHomeFiles(report *UnenrolReport, uid int, home string, owned []string) error {
	var failures []error
	for _, rel := range owned {
		path := filepath.Join(home, rel)
		spot, err := (hostfs.FS{}).EditedFile(path, uid, "")
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
			continue
		}
		present := spot.Info() != nil
		spot.Close()
		if !present {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
			continue
		}
		report.Record("agent configuration", true, path)
	}
	return errors.Join(failures...)
}
