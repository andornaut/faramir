package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/codextrust"
	"github.com/andornaut/faramir/internal/hostfs"
)

// Whether Codex has been told to trust the hooks an enrolment wrote. What that
// costs, and how Codex records it, is internal/codextrust; this is the finding.
//
// Failed rather than warned. A hook that does not run refuses nothing and
// routes nothing, which is what not installing it would have cost.

// codexHookFiles is every hook file this install wrote for Codex: the
// account-wide one and one per tree enrolled for it. A file that is not there
// is left out rather than reported, `agent rules` and `tree config` owning a
// tree that moved and a file that drifted.
func codexHookFiles(home string, trees []agentcfg.EnrolledTree) []string {
	var files []string
	if account := filepath.Join(home, agentcfg.CodexHooksFile); hostfs.Exists(account) {
		files = append(files, account)
	}
	for _, tree := range trees {
		if !slices.Contains(tree.Agents, "codex") {
			continue
		}
		if hooks := filepath.Join(tree.Dir, agentcfg.CodexHooksFile); hostfs.Exists(hooks) {
			files = append(files, hooks)
		}
	}
	sort.Strings(files)
	return files
}

// diagnoseCodexTrust reports every faramir hook Codex will not run: one it has
// not been told to trust, one whose identity has moved since it was trusted,
// and one turned off outright.
func diagnoseCodexTrust(report *Report, opts Options) {
	const label = "codex hook trust"
	if opts.AgentUser == "" {
		report.unaskedf(label, 1, "agent account unknown; not checked\n"+agentUnknown)
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(label, 1, "%s's home unreadable; not checked", opts.AgentUser)
		return
	}

	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	// The record is `tree config`'s to fail on. Said here so a report naming
	// only the account-wide hook does not read as a host with no enrolled trees.
	if err != nil {
		report.unaskedf(label, 1, "enrolled trees not checked, only the "+
			"account-wide hook\n%v", err)
	}
	reportCodexTrust(report, home, trees)
}

// reportCodexTrust is diagnoseCodexTrust against a home already resolved, every
// question being about files under a directory rather than about the passwd
// database.
func reportCodexTrust(report *Report, home string, trees []agentcfg.EnrolledTree) {
	const label = "codex hook trust"
	files := codexHookFiles(home, trees)
	if len(files) == 0 {
		report.addf(label, StatusNA, "no Codex hook installed")
		return
	}

	configFile := filepath.Join(home, codextrust.ConfigFile)
	state, err := codextrust.State(configFile)
	if err != nil {
		if os.IsPermission(err) {
			report.unaskedf(label, 1, "%s unreadable; run doctor through sudo", configFile)
			return
		}
		report.addf(label, StatusFailed, "%s does not parse\n%v", configFile, err)
		return
	}

	var trusted, untrusted, modified, disabled, unread []string
	for _, path := range files {
		hooks, err := codextrust.GuardHooks(path)
		switch {
		case err != nil && os.IsPermission(err):
			report.unaskedf(label, 1, "%s unreadable; run doctor through sudo", path)
			continue
		case err != nil:
			unread = append(unread, fmt.Sprintf("%s (%v)", path, err))
			continue
		// A file carrying no guard hook has drifted, which is `agent code`'s and
		// `tree config`'s finding rather than this one's: there is nothing here
		// left to trust.
		case len(hooks) == 0:
			continue
		}
		for _, hook := range hooks {
			entry, held := state[hook.Key]
			switch {
			case !held:
				untrusted = append(untrusted, hook.Path)
			case entry.TrustedHash != hook.Hash:
				modified = append(modified, hook.Path)
			case entry.Enabled != nil && !*entry.Enabled:
				disabled = append(disabled, hook.Path)
			default:
				trusted = append(trusted, hook.Path)
			}
		}
	}

	sort.Strings(untrusted)
	sort.Strings(modified)
	sort.Strings(disabled)
	sort.Strings(unread)

	if len(unread) > 0 {
		report.addf(label, StatusFailed, "%d Codex hook file(s) unreadable\n%s",
			len(unread), strings.Join(unread, "\n"))
	}
	if len(untrusted) > 0 {
		report.addf(label, StatusFailed, "Codex skips %d untrusted hook(s); "+
			"open Codex in each project and trust them in `/hooks`\n%s", len(untrusted), strings.Join(untrusted, "\n"))
	}
	if len(modified) > 0 {
		report.addf(label, StatusFailed, "Codex trusts a different hook than %d "+
			"installed here; open Codex in each project and trust them in `/hooks`\n%s", len(modified), strings.Join(modified, "\n"))
	}
	if len(disabled) > 0 {
		report.addf(label, StatusFailed, "%d hook(s) turned off in %s; remove "+
			"`enabled = false`, or re-enable them in Codex's `/hooks`\n%s",
			len(disabled), configFile, strings.Join(disabled, "\n"))
	}
	if len(untrusted) > 0 || len(modified) > 0 || len(disabled) > 0 || len(unread) > 0 {
		return
	}
	// Every hook file was there and readable and none of them carried a guard
	// hook, so there was nothing to be trusted and nothing was. "Codex trusts the
	// 0 hooks this install wrote" is true and reads as a pass, which is the wrong
	// answer for a host whose hooks have all been clobbered. Which file drifted is
	// `agent code`'s and `tree config`'s finding; this one says only that it has
	// no subject left.
	if len(trusted) == 0 {
		report.addf(label, StatusFailed, "none of %d Codex hook file(s) carries "+
			"the guard hook; run the enrolment that wrote them again", len(files))
		return
	}
	report.addf(label, StatusOK, "%d hook(s) trusted", len(trusted))
}
