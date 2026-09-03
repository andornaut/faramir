package doctor

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
)

// diagnoseDerivedPaths compares each derived [[secret.block]] entry with what
// its symlink resolves to now. The entry was written when the symlink was
// declared, and a rule matches the path a command names, so a symlink repointed
// since then leaves the old target blocked and the new one not, with nothing in
// the config to say so.
//
// Either direction is a match: a block entry derives the target from the
// symlink, and a link derives the spelling that was typed from the file the
// link names. A path that is not there, or that cannot be read, is not judged:
// a symlink on an unmounted volume has an entry that is right and waiting.
//
// Failed rather than a warning, for the reason the blocked paths check fails:
// the file the symlink names now is readable under that name. The fix named
// depends on the direction: declaring the symlink again replaces what a block
// entry derived, where a spelling a link derived is kept by the link for as
// long as the link names the file, and is removed by naming it.
func diagnoseDerivedPaths(report *Report, cfg *config.Config) {
	const name = "derived paths"
	checked := 0
	var drifted []string
	for _, entry := range cfg.Secret.Blocked {
		if entry.DerivedFrom == "" {
			continue
		}
		if _, err := os.Lstat(entry.DerivedFrom); err != nil {
			continue
		}
		if _, err := os.Lstat(entry.Path); err != nil {
			continue
		}
		checked++
		drift := derivedDrift(entry)
		if drift == "" {
			continue
		}
		if slices.ContainsFunc(cfg.Secret.Links, func(link config.Link) bool {
			return link.Path == entry.DerivedFrom
		}) {
			drift += fmt.Sprintf(" (`sudo faramir block rm --path %s` removes the entry)",
				config.Shown(entry.Path))
		} else {
			drift += fmt.Sprintf(" (`sudo faramir block add --path %s` replaces it)",
				config.Shown(entry.DerivedFrom))
		}
		drifted = append(drifted, drift)
	}
	switch {
	case len(drifted) > 0:
		report.addf(name, StatusFailed, "%d derived entr%s no longer name what "+
			"the symlink resolves to: %s",
			len(drifted), plural(len(drifted), "y", "ies"), strings.Join(drifted, "; "))
	case checked > 0:
		report.addf(name, StatusOK, "%d derived entr%s still name%s what the symlink "+
			"resolves to", checked, plural(checked, "y", "ies"), plural(checked, "s", ""))
	default:
		report.addf(name, StatusOK, "no derived [[secret.block]] entries are configured")
	}
}

// derivedDrift is what is wrong with one derived entry whose two paths are
// both there, or empty when nothing is: one of them resolves to the other.
func derivedDrift(entry config.BlockedPath) string {
	source, sourceIsLink := hostfs.SymlinkTarget(entry.DerivedFrom)
	if sourceIsLink && source == entry.Path {
		return ""
	}
	spelling, spellingIsLink := hostfs.SymlinkTarget(entry.Path)
	if spellingIsLink && spelling == entry.DerivedFrom {
		return ""
	}
	switch {
	case sourceIsLink:
		return fmt.Sprintf("%s now resolves to %s, and the entry derived from it "+
			"names %s", config.Shown(entry.DerivedFrom), config.Shown(source),
			config.Shown(entry.Path))
	case spellingIsLink:
		return fmt.Sprintf("%s now resolves to %s, not to %s, which it was derived "+
			"from", config.Shown(entry.Path), config.Shown(spelling),
			config.Shown(entry.DerivedFrom))
	}
	return fmt.Sprintf("neither %s nor %s is a symlink any more, and the entry for "+
		"the first was derived from the second", config.Shown(entry.Path),
		config.Shown(entry.DerivedFrom))
}

// plural is the suffix a count takes.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
