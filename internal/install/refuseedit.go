package install

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andornaut/faramir/internal/config"
)

// A [[secret.refuse]] entry against a [[secret.link]] one: both render the path
// into every agent's account-wide deny rules, and there the resemblance stops.
//
// A link grants the broker read on the file, regroups it so a brokered command
// is refused it, and puts the value in the redactor. This does none of that. It
// writes one entry and re-renders the rule files, so what it costs is a rule
// and what it buys is a rule.
//
// Which means the file's mode is left exactly as it was, and the value is
// absent from the redactor. A command the broker runs may still open the file
// if the mode allows, and what it prints comes back in the clear. That is the
// trade: reading the value to redact it would mean holding it, and these are
// the files whose value faramir should not hold.

// RefusedPathSteps is what an entry changes: the config it is written into,
// and the agent rule files rendered from it. No grant, so no step for one.
//
// Named for the entry rather than for the verb. In this package refuseX aborts
// a run because of X (refuseSymlinks, refuseUnwritable), so a name built the
// same way would read as the opposite of what this is.
func (r *runner) RefusedPathSteps() []namedStep {
	return []namedStep{
		{labelResolveIDs, r.resolveIDs},
		{labelPreconditions, r.stepPreconditions},
		{labelConfig, r.stepConfig},
		{labelAgentConfig, r.stepAgentConfig},
	}
}

// AddRefusedPath adds one entry and re-renders the rule files that name it.
//
// Nothing is read and nothing is granted, so there is no order to get right and
// nothing to put back on a failure: unlike AddLink, this either writes the
// entry and the rules or leaves the host as it was.
//
// A path the install already refuses is not an error. The entry stands, the
// rules are rendered again, and the report says nothing changed: the entry is
// the whole of what one names, so a second add asks for the state that is
// already there. Rendering again is the repair, restoring a rule an agent's
// settings dropped. The bool says which of the two happened.
//
// A path that is not there is added. These are keys on volumes that are not
// always mounted, and a rule costs nothing while its file is absent, so
// refusing one would refuse the case the entry exists for. The caller is told,
// because the other thing an absent path means is a typo.
func AddRefusedPath(opts Options, refused config.RefusedPath) (Report, bool, error) {
	if err := config.ValidateRefusedPath(refused); err != nil {
		return Report{}, false, err
	}
	configDir := configDirOr(opts.ConfigDir)
	configFile := filepath.Join(configDir, "config.toml")
	existing, err := config.BaseRefusedPaths(configFile)
	if err != nil {
		return Report{}, false, fmt.Errorf("%s: %w", configFile, err)
	}
	entries, added := refusedWith(existing, refused)
	// A link over the same file is not refused, both rendering the same rule,
	// but it is said: the link already refuses that path, and this entry adds
	// nothing the operator does not have.
	links, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, false, fmt.Errorf("%s: %w", configFile, err)
	}

	opts.refused, opts.refusedSet = entries, true
	if err := keepInstalledGrant(&opts, configDir); err != nil {
		return Report{}, false, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, false, err
	}
	report, err := run.apply(run.RefusedPathSteps())
	if err != nil {
		return report, false, err
	}
	// A name is not asked of the filesystem at all: it is matched against what an
	// agent names, which is why it reaches a path this host does not have. What
	// it will match is said instead, that being the thing a wide pattern hides.
	if refused.Name != "" {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s refuses %s. Nothing announces a pattern that matches more than it "+
				"was meant to: the agent meets it as file tools failing on files "+
				"nobody discussed", refused.Name, RefusedNameMatches(refused.Name)))
		return report, added, nil
	}
	if _, statErr := os.Stat(refused.Path); statErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is not there. The rule is written and will hold when it appears, "+
				"which is what an unmounted volume looks like. A path spelled wrong "+
				"looks the same, so check it", refused.Path))
	}
	for _, link := range links {
		if link.Path == refused.Path {
			report.Warnings = append(report.Warnings, fmt.Sprintf(
				"%s is already refused by the [[secret.link]] entry for %s, which "+
					"renders the same rule and also keeps the value out of any "+
					"output. This entry adds nothing to that", refused.Path, link.Ref))
		}
	}
	return report, added, nil
}

// refusedWith is the set an add renders and whether the path was new to it.
// One entry per path: the path is the whole of what an entry says, so a second
// one saying it again would render the same rule twice.
func refusedWith(existing []config.RefusedPath,
	refused config.RefusedPath) ([]config.RefusedPath, bool) {
	entries := append([]config.RefusedPath{}, existing...)
	for _, other := range existing {
		if sameRefusal(other, refused) {
			return entries, false
		}
	}
	return append(entries, refused), true
}

// sameRefusal is whether two entries ask for the same rule. The form counts as
// well as the string: a path and a name that read alike render different rules,
// so one does not stand in for the other.
func sameRefusal(a, b config.RefusedPath) bool {
	return a.Path == b.Path && a.Name == b.Name
}

// RemoveRefusedPath drops one entry and re-renders. It does not take the rule
// out of an agent's file: those are merged rather than replaced, so nothing
// here can remove an entry from one, and a rule carries no sign of who wrote
// it.
//
// A path the install does not refuse is not an error, for the reason a second
// add is not: what is asked for is the state the host is already in. The
// returned entry is the zero value there, which is how the caller tells the two
// apart.
func RemoveRefusedPath(opts Options, refused config.RefusedPath) (Report, config.RefusedPath, error) {
	configDir := configDirOr(opts.ConfigDir)
	configFile := filepath.Join(configDir, "config.toml")
	existing, err := config.BaseRefusedPaths(configFile)
	if err != nil {
		return Report{}, config.RefusedPath{}, fmt.Errorf("%s: %w", configFile, err)
	}
	kept := make([]config.RefusedPath, 0, len(existing))
	var removed config.RefusedPath
	for _, entry := range existing {
		if sameRefusal(entry, refused) {
			removed = entry
			continue
		}
		kept = append(kept, entry)
	}
	// kept is existing where nothing matched, so the steps below re-render what
	// is already there and report no change.
	opts.refused, opts.refusedSet = kept, true
	if err := keepInstalledGrant(&opts, configDir); err != nil {
		return Report{}, config.RefusedPath{}, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, config.RefusedPath{}, err
	}
	report, err := run.apply(run.RefusedPathSteps())
	return report, removed, err
}

// RefusedPaths is what the install declares, for `faramir refuse ls`.
func RefusedPaths(configDir string) ([]config.RefusedPath, error) {
	return config.BaseRefusedPaths(filepath.Join(configDirOr(configDir), "config.toml"))
}
