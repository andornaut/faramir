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
		{"resolveIDs", r.resolveIDs},
		{"preconditions", r.stepPreconditions},
		{"config", r.stepConfig},
		{"agent config", r.stepAgentConfig},
	}
}

// AddRefusedPath adds one entry and re-renders the rule files that name it.
//
// Nothing is read and nothing is granted, so there is no order to get right and
// nothing to put back on a failure: unlike AddLink, this either writes the
// entry and the rules or leaves the host as it was.
//
// A path that is not there is added. These are keys on volumes that are not
// always mounted, and a rule costs nothing while its file is absent, so
// refusing one would refuse the case the entry exists for. The caller is told,
// because the other thing an absent path means is a typo.
func AddRefusedPath(opts Options, refused config.RefusedPath) (Report, error) {
	if err := config.ValidateRefusedPath(refused); err != nil {
		return Report{}, err
	}
	configDir := configDirOr(opts.ConfigDir)
	configFile := filepath.Join(configDir, "config.toml")
	existing, err := config.BaseRefusedPaths(configFile)
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", configFile, err)
	}
	for _, other := range existing {
		if other.Path == refused.Path {
			return Report{}, fmt.Errorf("%s already refuses %s", configFile, refused.Path)
		}
	}
	// A link over the same file is not refused, both rendering the same rule,
	// but it is said: the link already refuses that path, and this entry adds
	// nothing the operator does not have.
	links, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", configFile, err)
	}

	opts.refused, opts.refusedSet = append(append([]config.RefusedPath{}, existing...), refused), true
	if err := keepInstalledGrant(&opts, configDir); err != nil {
		return Report{}, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, err
	}
	report, err := run.apply(run.RefusedPathSteps())
	if err != nil {
		return report, err
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
	return report, nil
}

// RemoveRefusedPath drops one entry and re-renders. It does not take the rule
// out of an agent's file: those are merged rather than replaced, so nothing
// here can remove an entry from one, and a rule carries no sign of who wrote
// it.
func RemoveRefusedPath(opts Options, path string) (Report, config.RefusedPath, error) {
	configDir := configDirOr(opts.ConfigDir)
	configFile := filepath.Join(configDir, "config.toml")
	existing, err := config.BaseRefusedPaths(configFile)
	if err != nil {
		return Report{}, config.RefusedPath{}, fmt.Errorf("%s: %w", configFile, err)
	}
	kept := make([]config.RefusedPath, 0, len(existing))
	var removed config.RefusedPath
	for _, entry := range existing {
		if entry.Path == path {
			removed = entry
			continue
		}
		kept = append(kept, entry)
	}
	if removed.Path == "" {
		return Report{}, config.RefusedPath{}, fmt.Errorf("%s refuses no path %q; "+
			"`faramir refuse ls` lists the ones it does", configFile, path)
	}

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
