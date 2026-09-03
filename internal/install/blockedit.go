package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/steps"
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

// blockedSteps is what an entry changes: the config it is written into,
// and the agent rule files rendered from it. No grant, so no step for one.
//
// Named for the entry rather than for the verb. In this package refuseX aborts
// a run because of X (refuseSymlinks, agentcfg.RefuseUnwritable), so a name built the
// same way would read as the opposite of what this is.
func (r *runner) blockedSteps() []steps.Named {
	return []steps.Named{
		{Name: steps.LabelResolveIDs, Run: r.resolveIDs},
		{Name: steps.LabelPreconditions, Run: r.stepPreconditions},
		{Name: steps.LabelConfig, Run: r.stepConfig},
		{Name: steps.LabelAgentConfig, Run: r.stepAgentConfig},
		// And the same rules in every tree already enrolled. An enrolment writes
		// this set into the tree as well as into the home, so without this the
		// home carried the new entry and every tree carried the set from before
		// it.
		{Name: steps.LabelEnrolledTrees, Run: r.stepEnrolledTrees},
		// Both entry points, because an entry feeds both: the agents' rule files
		// above, and the file the command guard reads here. Without this an add
		// reported changed while half of what it declared, or all of it for a
		// command, waited for the next `init`.
		{Name: "deny patterns", Run: r.stepDenyPatterns},
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
	links, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, nil, fmt.Errorf("%s: %w", configFile, err)
	}
	entries, added := foldBlocked(existing, refused)
	// The targets of whichever of them are symlinks, folded after the entries
	// that named them so that a target somebody also declared outright stays
	// the entry they wrote. What an earlier add derived from a symlink that has
	// since been repointed goes first, or the old target stays blocked beside
	// the new one.
	derived, skipped := derivations(configDir, refused)
	entries, stale, retained := replaceDerived(entries, refused, derived, links)
	entries, _ = foldBlocked(entries, derived)
	// A target the operator declared outright keeps its own entry, and the
	// warning says so rather than promising a cascade that will not happen.
	var declared []config.BlockedPath
	derived, declared = splitDeclared(entries, derived)

	opts.blocked, opts.blockedSet = entries, true
	if err := keepInstalledGrant(&opts, configDir); err != nil {
		return Report{}, nil, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, nil, err
	}
	report, err := run.apply(run.blockedSteps())
	if err != nil {
		return report, nil, err
	}
	for _, entry := range refused {
		blockedWarnings(&report, entry, links)
	}
	derivedWarnings(&report, derived, declared, skipped)
	for _, entry := range stale {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s no longer resolves to %s, so the entry an earlier add derived for "+
				"that path is removed", config.Shown(entry.DerivedFrom), config.Shown(entry.Path)))
	}
	derivedRemovalWarnings(&report, nil, retained, links)
	return report, added, nil
}

// replaceDerived takes out what an earlier add derived from a path that now
// resolves elsewhere, and answers with the entries that went and the ones that
// stayed because another entry still reaches their file. A symlink repointed
// since it was declared has an entry for its old target, and an add naming the
// link again is the operator asking for the file it names now: an entry for
// the file it named then is a rule for the wrong file, and a converge naming
// the link every run would otherwise carry it for good.
//
// Only a path that is there is judged. One that is absent may be a link on an
// unmounted volume, whose entry is right and waiting, and the derivation it
// stands for cannot be told from here.
func replaceDerived(entries, refused, derived []config.BlockedPath,
	links []config.Link) (kept, stale, retained []config.BlockedPath) {
	kept = entries
	for _, asked := range refused {
		if asked.Path == "" || strings.Contains(asked.Path, "*") {
			continue
		}
		if _, err := os.Lstat(asked.Path); err != nil {
			continue
		}
		// The symlink's own entry no longer explains the old target, so it is
		// left out of what may still reach it.
		others := slices.DeleteFunc(slices.Clone(kept), func(entry config.BlockedPath) bool {
			return entry.Path == asked.Path
		})
		rest := make([]config.BlockedPath, 0, len(kept))
		for _, entry := range kept {
			if entry.DerivedFrom != asked.Path || stillDerived(entry, derived) {
				rest = append(rest, entry)
				continue
			}
			if by, ok := reachedBy(entry, others, links); ok {
				entry.DerivedFrom = by
				rest = append(rest, entry)
				retained = append(retained, entry)
				continue
			}
			stale = append(stale, entry)
		}
		kept = rest
	}
	return kept, stale, retained
}

// stillDerived is whether an entry derived from the path an add names is what
// that add derives now. Either direction holds it: the add resolving the path
// to the entry's, which is a block entry's derivation, or the entry's path
// resolving to the add's, which is a link's, written for the spelling the link
// was typed under and explained by the target the add is declaring.
func stillDerived(entry config.BlockedPath, derived []config.BlockedPath) bool {
	if slices.ContainsFunc(derived, func(now config.BlockedPath) bool {
		return now.DerivedFrom == entry.DerivedFrom && now.Path == entry.Path
	}) {
		return true
	}
	target, ok := hostfs.SymlinkTarget(entry.Path)
	return ok && target == entry.DerivedFrom
}

// derivations is the target entry for each declared path that is a symlink, and
// the ones a target inside an enrolled tree left underived.
//
// A rule matches the path a command names, and a link and its target are two
// names for one file, so an entry for the link alone leaves the file readable
// under the other. The target is recorded as an entry of its own rather than
// resolved when a rule is rendered: the config is then what the rules are, which
// is what `block ls` reads and what an operator diffing two hosts compares.
//
// Every path that is not a symlink yields nothing. So does one that is not
// there, which is the case an entry is allowed to name and the case a wildcard
// entry always is: a pattern names no file to resolve, and the literal parent
// it is bounded by is already covered by the rule the entry renders.
func derivations(configDir string,
	refused []config.BlockedPath) (derived []config.BlockedPath, skipped []config.BlockedPath) {
	for _, entry := range refused {
		if entry.Path == "" || strings.Contains(entry.Path, "*") {
			continue
		}
		target, ok := hostfs.SymlinkTarget(entry.Path)
		if !ok {
			continue
		}
		resolved := config.BlockedPath{
			Path: target, Strict: entry.Strict, DerivedFrom: entry.Path,
		}
		if !derivable(configDir, resolved) {
			skipped = append(skipped, resolved)
			continue
		}
		derived = append(derived, resolved)
	}
	return derived, skipped
}

// splitDeclared parts the derived entries an add wrote from the ones that met
// an entry the operator declared outright, which foldBlocked leaves as it found
// it. The two are told apart by the entry the fold left: a declared one has no
// derived_from.
func splitDeclared(entries, derived []config.BlockedPath) (written, declared []config.BlockedPath) {
	for _, entry := range derived {
		i := slices.IndexFunc(entries, func(other config.BlockedPath) bool {
			return sameBlock(other, entry)
		})
		if i >= 0 && entries[i].DerivedFrom == "" {
			declared = append(declared, entry)
			continue
		}
		written = append(written, entry)
	}
	return written, declared
}

// derivable is whether an entry nobody typed may be written.
//
// Held to what an entry the operator writes is held to: a path that cannot be
// declared cannot be derived either, and rendering one would write a rule the
// next load refuses to read.
//
// And held to the tree rule for a reason the declared side does not have. The
// operator meets a refusal when they name a tree; this path was reached without
// anybody spelling it, and a dotfiles checkout is exactly the kind of directory
// a config symlink points at, so a rule here would refuse the agent every file
// in the directory it works in. A file inside a tree is the ordinary entry and
// is derived like any other.
func derivable(configDir string, entry config.BlockedPath) bool {
	if err := config.ValidateBlocked(entry); err != nil {
		return false
	}
	return refuseEnrolledTrees(configDir, []string{entry.Path}) == nil
}

// derivedWarnings says what an add wrote that nobody asked for by name, and what
// it declined to write. Both are worth a line: the first is an entry the
// operator will meet in `block ls` and in the config, and the second is a file
// still readable under a name the declared entry does not cover.
func derivedWarnings(report *Report, derived, declared, skipped []config.BlockedPath) {
	for _, entry := range derived {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is a symlink to %s, which is blocked as well: a rule matches the path "+
				"a command names, and either spelling opens the file. `faramir block rm "+
				"--path %s` takes both while nothing else names the file",
			config.Shown(entry.DerivedFrom), config.Shown(entry.Path),
			config.Shown(entry.DerivedFrom)))
	}
	for _, entry := range declared {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is a symlink to %s, which has an entry of its own. That entry stays "+
				"when this one is removed",
			config.Shown(entry.DerivedFrom), config.Shown(entry.Path)))
	}
	for _, entry := range skipped {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is a symlink to %s, which is not blocked: it is an enrolled tree or a "+
				"path no entry may name, and a rule for it would refuse the agent the "+
				"directory it works in. A command naming the target reaches the file",
			config.Shown(entry.DerivedFrom), config.Shown(entry.Path)))
	}
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
			if !coversPath(path, tree.Dir) {
				continue
			}
			if path == tree.Dir {
				return fmt.Errorf("path %s is an enrolled tree. The rules apply "+
					"wherever the agent works, so it would be refused every file in "+
					"its own working directory. Name the file inside it, or "+
					"`sudo faramir enrol` elsewhere first", path)
			}
			return fmt.Errorf("path %s holds the enrolled tree %s, so the rule would "+
				"refuse the agent every file in the directory it works in. Name the "+
				"file or the directory that holds it", path, tree.Dir)
		}
	}
	return nil
}

// coversPath reports whether the rule an entry renders would reach inner. It is
// containsPath for a literal entry, and a prefix match for the trailing-wildcard
// form, which containsPath answers "no" for while the rendered rule answers
// "yes": filepath.Rel compares path elements, so "/home/op/pro*" does not hold
// "/home/op/project" by that reading, and DirUnder's subject matches every file
// in it. An entry that reached a tree without ever spelling its name was
// accepted here and refused the agent its whole checkout after the reload.
//
// The prefix is compared against the literal rather than the entry: the
// wildcard opens the end of the last component, so any tree whose path begins
// with that literal is reached, whether the rest of the component follows it or
// a separator does.
func coversPath(entry, inner string) bool {
	if literal, isPrefix := denyrules.TrailingPrefix(entry); isPrefix {
		return strings.HasPrefix(filepath.Clean(inner), literal)
	}
	return containsPath(entry, inner)
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
		// A derivation is not an operator asking for anything, so it changes an
		// entry only where it owns one. Over an entry that was declared it says
		// nothing at all: a target declared strict under a link that is not would
		// otherwise be loosened here and tightened again by the next converge,
		// reported changed both times and never settling.
		if refused.DerivedFrom != "" {
			if other.DerivedFrom == "" {
				return entries, false
			}
			if other.Strict != refused.Strict {
				entries[i].Strict = refused.Strict
				return entries, true
			}
			return entries, false
		}
		changed := false
		if other.Strict != refused.Strict {
			entries[i].Strict = refused.Strict
			changed = true
		}
		// An operator declaring a path an earlier add derived takes it over: the
		// entry stops being the link's, so a `block rm` of the link leaves it
		// standing.
		if other.DerivedFrom != "" {
			entries[i].DerivedFrom = ""
			changed = true
		}
		return entries, changed
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
	links, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, nil, fmt.Errorf("%s: %w", configFile, err)
	}
	kept, removed, cascaded, retained := withoutBlocked(existing, refused, links)
	for i, asked := range refused {
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
	report, err := run.apply(run.blockedSteps())
	// An install that declared what faramir already refuses has one rule left
	// after taking its entry back. Said here rather than left to be inferred from
	// the entry going away, which reads as the file becoming readable.
	if err == nil {
		derivedRemovalWarnings(&report, cascaded, retained, links)
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

// withoutBlocked is the set a removal leaves, the entry each ask matched, the
// derived entries that went with them, and the derived entries that stayed
// because something else still reaches their file.
//
// removed is one entry per ask, in the order they were given, and the zero value
// where nothing matched: the caller tells "removed" from "was not there" by
// that, and answers the second differently.
//
// A derived entry is not asked for by name. It was written because the declared
// path resolved to it, so it goes when that path does, or the host is left with
// a rule no entry explains and a converge reporting one nobody declared. An ask
// naming the derived path directly still removes it, sameBlock matching on the
// path: what comes back then is an entry the next add derives again. An entry
// derived from a path no block entry declares belongs to a link, and is that
// link's to remove.
func withoutBlocked(existing, refused []config.BlockedPath,
	links []config.Link) (kept, removed, cascaded, retained []config.BlockedPath) {
	removed = make([]config.BlockedPath, len(refused))
	kept = make([]config.BlockedPath, 0, len(existing))
	var orphaned []string
	for _, entry := range existing {
		i := slices.IndexFunc(refused, func(asked config.BlockedPath) bool {
			return sameBlock(entry, asked)
		})
		if i < 0 {
			kept = append(kept, entry)
			continue
		}
		removed[i] = entry
		if entry.Path != "" {
			orphaned = append(orphaned, entry.Path)
		}
	}
	kept, cascaded, retained = reclaimDerived(kept, links, orphaned)
	return kept, removed, cascaded, retained
}

// reclaimDerived settles the derived entries whose source was taken away: each
// one derived from a path in orphaned is dropped, unless a kept entry still
// reaches its file, in which case it stays and derived_from names that entry
// instead. Only those are looked at, so a removal takes nothing but what the ask
// names and what was written for it. An entry that goes is a source taken away
// in turn, so what was derived from it is settled the same way.
//
// Two symlinks to one file derive one entry, and removing the entry for one of
// them must leave the file blocked under the other's name. Two links through
// one symlink share the entry for the typed spelling the same way.
func reclaimDerived(entries []config.BlockedPath, links []config.Link,
	orphaned []string) (kept, cascaded, retained []config.BlockedPath) {
	kept = entries
	for len(orphaned) > 0 {
		var next []string
		rest := make([]config.BlockedPath, 0, len(kept))
		for _, entry := range kept {
			if entry.DerivedFrom == "" || !slices.Contains(orphaned, entry.DerivedFrom) {
				rest = append(rest, entry)
				continue
			}
			by, ok := reachedBy(entry, kept, links)
			if !ok {
				cascaded = append(cascaded, entry)
				next = append(next, entry.Path)
				continue
			}
			entry.DerivedFrom = by
			rest = append(rest, entry)
			retained = append(retained, entry)
		}
		kept, orphaned = rest, next
	}
	return kept, cascaded, retained
}

// reachedBy is the path of an entry that still reaches a derived entry's file,
// which is when the derived entry stays through a removal: a block entry naming
// the path it was derived from, a link at that path, or a declared block entry
// that is a symlink resolving to it. A link at the derived path itself is not
// one: it renders the same rule, and a block entry beside it says nothing the
// link does not. Nor is a derived entry that is a symlink, which is the
// spelling such a link was typed under: two derived entries reaching each other
// would outlive everything that was declared.
//
// A declared block entry that cannot be read counts as reaching. Nothing here
// can tell where it points, and a rule kept for a file nobody names costs a row
// in `block ls`, where a rule dropped from under an entry costs the file being
// readable under its other name.
func reachedBy(derived config.BlockedPath, entries []config.BlockedPath,
	links []config.Link) (string, bool) {
	for _, link := range links {
		if link.Path == derived.DerivedFrom {
			return link.Path, true
		}
	}
	for _, entry := range entries {
		if entry.Path == "" || sameBlock(entry, derived) {
			continue
		}
		if entry.Path == derived.DerivedFrom {
			return entry.Path, true
		}
		if entry.DerivedFrom != "" || strings.Contains(entry.Path, "*") {
			continue
		}
		if info, err := os.Lstat(entry.Path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return entry.Path, true
			}
			continue
		} else if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if target, ok := hostfs.SymlinkTarget(entry.Path); ok && target == derived.Path {
			return entry.Path, true
		}
	}
	return "", false
}

// derivedRemovalWarnings says what a removal did with the entries nobody asked
// for by name: which went with the entry they were written for, and which
// stayed because another entry still reaches their file. Both are worth a line.
// The first is a rule the operator may have been counting on, and the second is
// an entry the add promised would go with its symlink and did not.
//
// A file a link still names is not reported as unblocked: the link renders the
// same rule, so what went was an entry saying what the link already says.
func derivedRemovalWarnings(report *Report, cascaded, retained []config.BlockedPath,
	links []config.Link) {
	for _, entry := range cascaded {
		if i := slices.IndexFunc(links, func(link config.Link) bool {
			return link.Path == entry.Path
		}); i >= 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf(
				"the entry for %s went with %s, which resolved to it. The file is still "+
					"refused by the [[secret.link]] entry for %s",
				config.Shown(entry.Path), config.Shown(entry.DerivedFrom),
				config.Shown(links[i].Ref)))
			continue
		}
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is no longer blocked either: it is what %s resolved to, and the "+
				"entry for it was written for that one",
			config.Shown(entry.Path), config.Shown(entry.DerivedFrom)))
	}
	for _, entry := range retained {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s is still blocked: %s still names the same file, and the entry for it "+
				"goes with that one",
			config.Shown(entry.Path), config.Shown(entry.DerivedFrom)))
	}
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
	return fmt.Errorf("%s is under %s, faramir's own install directory. It is "+
		"blocked by the install layout, not by a [[secret.block]] entry, so there "+
		"is nothing to remove and it stays blocked. `faramir block ls` shows which "+
		"rules come from the layout", config.Shown(refused.Blocks()), dir)
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
