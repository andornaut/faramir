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
		report.unaskedf(label, 1, "the agent account is not named, so what "+
			"Codex trusts was not checked. Run doctor through sudo (SUDO_USER names the "+
			"account), or record it with `sudo faramir init --agent-user`")
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(label, 1, "could not read %s's home, so what Codex "+
			"trusts was not checked", opts.AgentUser)
		return
	}

	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	// The record is `tree config`'s to fail on. Said here so a report naming
	// only the account-wide hook does not read as a host with no enrolled trees.
	if err != nil {
		report.unaskedf(label, 1, "%s, so which trees are enrolled for Codex is "+
			"unknown and only the account-wide hook was examined", err)
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
		report.addf(label, StatusNA, "no Codex hook is installed, so there is "+
			"nothing for Codex to trust")
		return
	}

	configFile := filepath.Join(home, codextrust.ConfigFile)
	state, err := codextrust.State(configFile)
	if err != nil {
		if os.IsPermission(err) {
			report.unaskedf(label, 1, "%s could not be read, so what Codex "+
				"trusts was not checked. Re-run doctor through sudo", configFile)
			return
		}
		report.addf(label, StatusFailed, "%s does not parse, so whether Codex "+
			"runs the %d hook(s) this install wrote is unknown: %v",
			configFile, len(files), err)
		return
	}

	var trusted, untrusted, modified, disabled, unread []string
	for _, path := range files {
		hooks, err := codextrust.GuardHooks(path)
		switch {
		case err != nil && os.IsPermission(err):
			report.unaskedf(label, 1, "%s could not be read, so whether Codex "+
				"runs it was not checked. Re-run doctor through sudo", path)
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
		report.addf(label, StatusFailed, "%d Codex hook file(s) could not be "+
			"read, so whether Codex runs them is unknown: %s",
			len(unread), strings.Join(unread, ", "))
	}
	if len(untrusted) > 0 {
		report.addf(label, StatusFailed, "Codex has not been told to trust %d "+
			"hook(s) this install wrote, so it skips them and says nothing: %s. Nothing "+
			"in those trees is refused or routed. Start Codex once in each and accept its "+
			"trust prompt; no flag or config key does this",
			len(untrusted), strings.Join(untrusted, ", "))
	}
	if len(modified) > 0 {
		report.addf(label, StatusFailed, "Codex trusts a different hook than "+
			"the %d installed here, so it skips the one on disk: %s. A release that "+
			"rewrites the hook causes this. Start Codex once in each and trust the hook "+
			"again",
			len(modified), strings.Join(modified, ", "))
	}
	if len(disabled) > 0 {
		report.addf(label, StatusFailed, "%d hook(s) this install wrote are turned "+
			"off in %s, so Codex loads them and runs nothing: %s. Remove the "+
			"`enabled = false` entry, or re-enable the hook from Codex",
			len(disabled), configFile, strings.Join(disabled, ", "))
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
		report.addf(label, StatusFailed, "%d Codex hook file(s) are installed "+
			"and none carries the guard hook, so nothing is routed or refused and there "+
			"is nothing for Codex to trust. Re-run the enrolment that wrote them", len(files))
		return
	}
	report.addf(label, StatusOK, "Codex trusts the %d hook(s) this install wrote",
		len(trusted))
}
