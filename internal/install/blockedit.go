package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
)

// A [[secret.block]] entry against a [[secret.link]] one: both render the path
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

// BlockedSteps is what an entry changes: the config it is written into,
// and the agent rule files rendered from it. No grant, so no step for one.
//
// Named for the entry rather than for the verb. In this package refuseX aborts
// a run because of X (refuseSymlinks, agentcfg.RefuseUnwritable), so a name built the
// same way would read as the opposite of what this is.
func (r *runner) BlockedSteps() []namedStep {
	return []namedStep{
		{labelResolveIDs, r.resolveIDs},
		{labelPreconditions, r.stepPreconditions},
		{labelConfig, r.stepConfig},
		{labelAgentConfig, r.stepAgentConfig},
		// And the same rules in every tree already enrolled. An enrolment writes
		// this set into the tree as well as into the home, so without this the
		// home carried the new entry and every tree carried the set from before
		// it.
		{labelEnrolledTrees, r.stepEnrolledTrees},
		// Both entry points, because an entry feeds both: the agents' rule files
		// above, and the file the command guard reads here. Without this an add
		// reported changed while half of what it declared, or all of it for a
		// command, waited for the next `init`.
		{"deny patterns", r.stepDenyPatterns},
	}
}

// AddBlockedPaths adds entries and re-renders the rule files that name them,
// taking several at once because that is what a first run pastes and what a
// converge hands over: a dozen names is a dozen rules and one host to change.
//
// Nothing is read and nothing is granted, so there is no order to get right and
// nothing to put back on a failure: unlike AddLink, this either writes the
// entries and the rules or leaves the host as it was. Every entry is held to
// the loader's rules before anything is written, so a list carrying one bad
// entry writes none of it. The config and the rule files are then rendered once
// rather than once per entry, which is the difference between one changed
// report and a dozen.
//
// A path the install already refuses is not an error. The entry stands, the
// rules are rendered again, and the report says nothing changed: the entry is
// the whole of what one names, so a second add asks for the state that is
// already there. Rendering again is the repair, restoring a rule an agent's
// settings dropped. The bools are per entry, in the order given, and say which
// were new.
//
// A path that is not there is added. These are keys on volumes that are not
// always mounted, and a rule costs nothing while its file is absent, so
// refusing one would refuse the case the entry exists for. The caller is told,
// because the other thing an absent path means is a typo.
func AddBlockedPaths(opts Options, refused []config.BlockedPath) (Report, []bool, error) {
	if len(refused) == 0 {
		return Report{}, nil, errors.New("name a path or a command to refuse")
	}
	for _, entry := range refused {
		if err := config.ValidateBlocked(entry); err != nil {
			return Report{}, nil, err
		}
	}
	configDir := configDirOr(opts.ConfigDir)
	if err := refuseEnrolledTrees(configDir, blockedPathsOf(refused)); err != nil {
		return Report{}, nil, err
	}
	configFile := filepath.Join(configDir, "config.toml")
	if err := recordConfigDigest(&opts, configFile); err != nil {
		return Report{}, nil, err
	}
	existing, err := config.BaseBlocked(configFile)
	if err != nil {
		return Report{}, nil, fmt.Errorf("%s: %w", configFile, err)
	}
	entries, added := foldBlocked(existing, refused)
	// A link over the same file is not refused, both rendering the same rule,
	// but it is said: the link already refuses that path, and this entry adds
	// nothing the operator does not have.
	links, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, nil, fmt.Errorf("%s: %w", configFile, err)
	}

	opts.blocked, opts.blockedSet = entries, true
	if err := keepInstalledGrant(&opts, configDir); err != nil {
		return Report{}, nil, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, nil, err
	}
	report, err := run.apply(run.BlockedSteps())
	if err != nil {
		return report, nil, err
	}
	for _, entry := range refused {
		blockedWarnings(&report, entry, links)
	}
	return report, added, nil
}

// refuseEnrolledTrees stops a path entry that would refuse the agent the tree
// it works in, or a directory holding one. The rules hold wherever the agent
// works, so it meets one as every file tool failing in the directory it was
// pointed at, with a rule it can read and cannot lift.
//
// Refused rather than warned, as "/" is: an entry naming a checkout refuses
// nothing that is a secret, and the file inside it worth refusing can be named
// on its own. A directory under a tree is left alone, that being the ordinary
// entry: `--path ~/proj/.env` is what this is for.
func refuseEnrolledTrees(configDir string, paths []string) error {
	trees := agentcfg.ReadEnrolled(configDir)
	if len(trees) == 0 {
		return nil
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		for _, tree := range trees {
			if !containsPath(path, tree.Dir) {
				continue
			}
			if path == tree.Dir {
				return fmt.Errorf("path %s is an enrolled tree, and the rules hold "+
					"wherever the agent works: it would be refused every file in the "+
					"directory it works in. Name the file inside it, or "+
					"`sudo faramir init-project` elsewhere first", path)
			}
			return fmt.Errorf("path %s holds the enrolled tree %s, so the rule would "+
				"refuse the agent every file in the directory it works in. Name the "+
				"file or the directory that holds it", path, tree.Dir)
		}
	}
	return nil
}

// containsPath reports whether inner is dir itself or somewhere under it, by
// path element: /home/op2 is not under /home/op.
func containsPath(dir, inner string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(inner))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// blockedWarnings is what one entry is worth saying about once it is written.
func blockedWarnings(report *Report, refused config.BlockedPath, links []config.Link) {
	// A name is not asked of the filesystem at all: it is matched against what an
	// agent names, which is why it reaches a path this host does not have. What
	// it will match is said instead, that being the thing a wide pattern hides.
	if refused.Command != "" {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s blocks the agent's shell from running it. The words are literal and "+
				"are matched where a command starts, so a line that names them without "+
				"running them, a grep or an editor's argument, is left alone",
			config.Shown(refused.Command)))
		return
	}
	if _, statErr := os.Stat(refused.Path); statErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is not there. The rule is written and will hold when it appears, "+
				"which is what an unmounted volume looks like. A path spelled wrong "+
				"looks the same, so check it", config.Shown(refused.Path)))
	}
	for _, link := range links {
		if link.Path == refused.Path {
			report.Warnings = append(report.Warnings, fmt.Sprintf(
				"%s is already refused by the [[secret.link]] entry for %s, which "+
					"renders the same rule and also keeps the value out of any "+
					"output. This entry adds nothing to that", config.Shown(refused.Path), config.Shown(link.Ref)))
		}
	}
}

// blockedWith is the set an add renders and whether the path was new to it.
// One entry per path: the path is the whole of what an entry says, so a second
// one saying it again would render the same rule twice.
func blockedWith(existing []config.BlockedPath,
	refused config.BlockedPath) ([]config.BlockedPath, bool) {
	entries := append([]config.BlockedPath{}, existing...)
	for i, other := range existing {
		if !sameBlock(other, refused) {
			continue
		}
		// The same rule, and the entry says how strictly it is matched. An add
		// naming a stricter or looser one is a change to the entry rather than a
		// second entry for the same file, in both directions: what a converge
		// names every run is the state it wants, and a --strict dropped from
		// the list means the operator stopped asking for it. Reported as changed,
		// or an operator who tightened a rule is told nothing happened.
		if other.Strict != refused.Strict {
			entries[i].Strict = refused.Strict
			return entries, true
		}
		return entries, false
	}
	return append(entries, refused), true
}

// foldBlocked is the set an add renders and which of the entries were new to
// it. Folded one at a time against what the last one left, so a list naming the
// same entry twice adds it once and reports the second as already there, the
// way two commands run in that order would.
func foldBlocked(existing,
	asked []config.BlockedPath) ([]config.BlockedPath, []bool) {
	entries := existing
	added := make([]bool, len(asked))
	for i, entry := range asked {
		entries, added[i] = blockedWith(entries, entry)
	}
	return entries, added
}

// sameBlock is whether two entries ask for the same rule. Every form, and the
// form counts as well as the string: a path and a name that read alike render
// different rules, so one does not stand in for the other, and two commands
// that share an empty path and an empty name are not the same command.
//
// Not strict, which is how strictly the rule is matched rather than what
// it names. Two entries for one path is what the loader refuses; blockedWith is
// where the strictness of the one entry is settled.
func sameBlock(a, b config.BlockedPath) bool {
	return a.Path == b.Path && a.Command == b.Command
}

// RemoveBlockedPaths drops entries and re-renders, the counterpart of
// AddBlockedPaths: one config rewrite and one render, whatever the length. It
// does not take the rule out of an agent's file: those are merged rather than
// replaced, so nothing here can remove an entry from one, and a rule carries no
// sign of who wrote it.
//
// A path the install does not refuse is not an error, for the reason a second
// add is not: what is asked for is the state the host is already in. The
// returned entry is the zero value there, which is how the caller tells the two
// apart.
//
// A built-in rule is the exception and fails. It is refused by faramir itself
// rather than by an entry, so there is nothing here to remove and the host goes
// on refusing it: reporting that as "not refused, nothing removed" would answer
// a request to stop refusing something with a sentence saying it was never
// refused, and leave the operator to find out otherwise from an agent. Removing
// one means changing faramir, which is not something a host's config can ask
// for. The refusal covers the whole list before anything is written, so a list
// holding one of those removes nothing rather than removing what it could and
// failing halfway.
func RemoveBlockedPaths(opts Options, refused []config.BlockedPath) (Report, []config.BlockedPath, error) {
	configDir := configDirOr(opts.ConfigDir)
	configFile := filepath.Join(configDir, "config.toml")
	if len(refused) == 0 {
		return Report{}, nil, errors.New("name a path or a command to stop refusing")
	}
	if err := recordConfigDigest(&opts, configFile); err != nil {
		return Report{}, nil, err
	}
	existing, err := config.BaseBlocked(configFile)
	if err != nil {
		return Report{}, nil, fmt.Errorf("%s: %w", configFile, err)
	}
	kept := existing
	removed := make([]config.BlockedPath, len(refused))
	for i, asked := range refused {
		rest := make([]config.BlockedPath, 0, len(kept))
		for _, entry := range kept {
			if sameBlock(entry, asked) {
				removed[i] = entry
				continue
			}
			rest = append(rest, entry)
		}
		kept = rest
		// Asked before anything is written, and only where no entry matched: an
		// install that declared the same rule as well may take its own entry back,
		// and what it is left with is the layout's, which the warning below says.
		if removed[i].Blocks() == "" {
			if err := builtInRuleError(configDir, asked); err != nil {
				return Report{}, nil, err
			}
		}
	}
	// kept is existing where nothing matched, so the steps below re-render what
	// is already there and report no change.
	opts.blocked, opts.blockedSet = kept, true
	if err := keepInstalledGrant(&opts, configDir); err != nil {
		return Report{}, nil, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, nil, err
	}
	report, err := run.apply(run.BlockedSteps())
	// An install that declared what faramir already refuses has one rule left
	// after taking its entry back. Said here rather than left to be inferred from
	// the entry going away, which reads as the file becoming readable.
	if err == nil {
		for _, entry := range removed {
			if entry.Blocks() == "" {
				continue
			}
			if dir, ok := agentcfg.InstalledDirCovering(configDir, entry.Path); ok {
				report.Warnings = append(report.Warnings, fmt.Sprintf(
					"%s is still blocked: it is under %s, which this install occupies and "+
						"renders a rule for on every run. What was removed is this install's "+
						"own entry, which was asking for what the layout already blocks",
					config.Shown(entry.Blocks()), dir))
			}
		}
	}
	return report, removed, err
}

// BuiltInRuleError is why a request to stop refusing something cannot be
// met, or nil where it can. For the command, which asks before it asks for
// root: a request that can never be granted has no business costing a sudo
// first. RemoveBlockedPaths asks again at the write, from the same function
// below, for a caller that is not the command.
//
// The install's own entries are read first and win. An install may declare what
// faramir already refuses, and taking that entry back is a request it can meet:
// what it is left with is the built-in, which the removal names. Refusing here
// on the strength of the built-in alone would make an entry the install carries
// unremovable, which is the bug this guards.
//
// A config that does not load leaves this to the write, where the error names
// the config rather than the rule. One that is absent is a host declaring none,
// which is a different thing and gets the built-in answer.
func BuiltInRuleError(configDir string, refused config.BlockedPath) error {
	declared, err := BlockedPaths(configDir)
	if err != nil {
		// Deliberately not this function's error to report: the write is about to
		// fail on the same config and say so naming the file, which is the fault
		// to fix. Answering here with a rule would send the operator to the wrong
		// one.
		//nolint:nilerr // see above
		return nil
	}
	for _, entry := range declared {
		if sameBlock(entry, refused) {
			return nil
		}
	}
	return builtInRuleError(configDir, refused)
}

// builtInRuleError is the rule half of the question, with no config in it.
//
// The question is about the rule rather than the entry: "stop refusing
// ~/.ssh/id_rsa" is answered by what renders that rule, which may be a
// directory this install occupies rather than anything the config declares.
func builtInRuleError(configDir string, refused config.BlockedPath) error {
	dir, ok := agentcfg.InstalledDirCovering(configDir, refused.Path)
	if !ok {
		return nil
	}
	return fmt.Errorf("%s is under %s, which this install occupies, so it is "+
		"blocked by the layout rather than by a [[secret.block]] entry: there is "+
		"nothing here to remove and the host goes on blocking it. Those rules are "+
		"rendered on every run and change only with the install; `faramir block "+
		"ls` shows which rules are which", config.Shown(refused.Blocks()), dir)
}

// BlockedPaths is what the install declares, for `faramir block ls`.
func BlockedPaths(configDir string) ([]config.BlockedPath, error) {
	return config.BaseBlocked(filepath.Join(configDirOr(configDir), "config.toml"))
}

// blockedPathsOf is the path each entry names, skipping the command entries,
// which name none.
func blockedPathsOf(refused []config.BlockedPath) []string {
	out := make([]string, 0, len(refused))
	for _, entry := range refused {
		if entry.Path != "" {
			out = append(out, entry.Path)
		}
	}
	return out
}
