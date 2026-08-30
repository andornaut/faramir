package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Whether Codex has been told to trust the hooks an enrolment wrote.
//
// This is the one thing an enrolment installs that fails with no signal
// anywhere else. Every other misconfiguration surfaces as a refusal, a failed
// play or a degraded ref; a hook Codex has not been told to trust is skipped
// without a word, so an unguarded Codex runs normally and looks like a guarded
// one from every direction an operator would think to look.
//
// The trigger is routine. The hook assets are templates: a release that adjusts
// the guard invocation rewrites them, which changes the identity Codex hashes
// and drops trust across every enrolled tree on the same run that installed the
// new binary. `init-project` in a new checkout writes a hook that starts
// untrusted for the same reason.
//
// Failed rather than warned. A hook that does not run refuses nothing and
// routes nothing, which is what not installing it would have cost.

// codexConfigFile is where Codex records what it has been told to trust, under
// the home of the account that runs it. Written by Codex itself when the
// operator answers its prompt; there is no subcommand or config key that grants
// this, which is why doctor reports it rather than init writing it.
const codexConfigFile = ".codex/config.toml"

// codexTrustEvent is PreToolUse as Codex labels it in a state key and in the
// identity it hashes. The only event faramir registers for.
const codexTrustEvent = "pre_tool_use"

// codexGuardMarker identifies faramir's own registration inside a hook file
// that may carry the operator's hooks as well. Both halves of the enrolment run
// the guard in Codex's dialect; the account-wide one adds --deny-only.
const codexGuardMarker = "faramir guard --host codex"

// What Codex fills in for a command hook it parsed, which is what it hashes
// rather than the file's bytes.
const (
	// An absent timeout on every event but SessionEnd and Interrupt, neither of
	// which faramir registers for.
	codexDefaultHookTimeout = 600
	// A context limit equal to the default is dropped from the identity, so the
	// file setting it and the file omitting it hash alike.
	codexDefaultContextLimit = 2500
)

// codexHandler is one hook handler as Codex parses it. Only the keys Codex
// carries into the hashed identity: it ignores what it does not define, and a
// key faramir kept would hash to something Codex never computes.
type codexHandler struct {
	Type                   string  `json:"type"`
	Command                string  `json:"command"`
	Timeout                *int64  `json:"timeout"`
	Async                  bool    `json:"async"`
	StatusMessage          *string `json:"statusMessage"`
	AdditionalContextLimit *int64  `json:"additionalContextLimit"`
}

// codexMatcherGroup is one entry of an event's array: which tools it answers
// for and the handlers that answer.
type codexMatcherGroup struct {
	Matcher *string        `json:"matcher"`
	Hooks   []codexHandler `json:"hooks"`
}

// codexHooksFileDoc is a hooks.json as Codex reads it. PreToolUse alone: the
// other events are the operator's, and each is trusted on its own key.
type codexHooksFileDoc struct {
	Hooks struct {
		PreToolUse []codexMatcherGroup `json:"PreToolUse"`
	} `json:"hooks"`
}

// codexConfigDoc is the trust state Codex keeps. Every other key in that file
// is Codex's own and is not read here.
type codexConfigDoc struct {
	Hooks struct {
		State map[string]codexHookState `toml:"state"`
	} `toml:"hooks"`
}

// codexHookState is what Codex records per hook: the identity it was told to
// trust, and whether the hook is turned on at all. A disabled hook does not run
// however well it is trusted.
type codexHookState struct {
	Enabled     *bool  `toml:"enabled"`
	TrustedHash string `toml:"trusted_hash"`
}

// codexGuardHook is one faramir registration inside a hook file: the key Codex
// records its trust under, and the identity that key has to hold.
type codexGuardHook struct {
	Path string
	Key  string
	Hash string
}

// canonicalJSON is the encoding Codex hashes: compact, every object's keys
// sorted, and no HTML escaping. Go's encoder sorts a map's keys already and
// escapes <, > and & by default, which the encoder Codex uses does not, so a
// command carrying a redirection would otherwise hash to something Codex never
// computes.
func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// codexHandlerIdentity is one handler as Codex holds it after parsing, which is
// what goes into the hash. The normalization is Codex's:
//
//   - the Windows command is always unset, so it is never in the identity
//   - an absent timeout becomes 600, and any timeout is at least 1
//   - async is always present, false where the file omits it
//   - a status message and a context limit are carried only where the file sets
//     them, and a context limit equal to the default is dropped
//
// A key the handler does not define is absent rather than null: the identity
// goes through TOML on the way to being hashed, and TOML has no null.
func codexHandlerIdentity(handler codexHandler) map[string]any {
	timeout := int64(codexDefaultHookTimeout)
	if handler.Timeout != nil {
		timeout = *handler.Timeout
	}
	if timeout < 1 {
		timeout = 1
	}
	identity := map[string]any{
		"type":    "command",
		"command": handler.Command,
		"timeout": timeout,
		"async":   handler.Async,
	}
	if handler.StatusMessage != nil {
		identity["statusMessage"] = *handler.StatusMessage
	}
	if handler.AdditionalContextLimit != nil &&
		*handler.AdditionalContextLimit != codexDefaultContextLimit {
		identity["additionalContextLimit"] = *handler.AdditionalContextLimit
	}
	return identity
}

// codexTrustHash is the identity Codex records as trusted: sha256 over the
// canonical JSON of the matcher group carrying this one handler, flattened
// under the event's key label.
//
// The group's own hooks array is replaced by the single handler being hashed,
// so trust is per handler rather than per file: adding a second hook beside
// faramir's leaves faramir's identity alone.
func codexTrustHash(matcher *string, handler codexHandler) (string, error) {
	identity := map[string]any{
		"event_name": codexTrustEvent,
		"hooks":      []any{codexHandlerIdentity(handler)},
	}
	// An absent matcher is absent from the identity for the reason an absent
	// timeout would be: the identity is TOML before it is JSON.
	if matcher != nil {
		identity["matcher"] = *matcher
	}
	body, err := canonicalJSON(identity)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// codexGuardHooks is every PreToolUse handler in this file that runs faramir's
// guard, with the key Codex records each one's trust under. The file is merged
// rather than written whole, so the position is read from the file rather than
// assumed: Codex keys a hook by where it sits in the array.
func codexGuardHooks(path string) ([]codexGuardHook, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc codexHooksFileDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var found []codexGuardHook
	for group, entry := range doc.Hooks.PreToolUse {
		for handler, hook := range entry.Hooks {
			if hook.Type != "command" || !strings.Contains(hook.Command, codexGuardMarker) {
				continue
			}
			hash, err := codexTrustHash(entry.Matcher, hook)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			found = append(found, codexGuardHook{
				Path: path,
				Key:  fmt.Sprintf("%s:%s:%d:%d", path, codexTrustEvent, group, handler),
				Hash: hash,
			})
		}
	}
	return found, nil
}

// codexTrustState is what the agent's Codex config records. A file that is not
// there is the ordinary state of an account that has trusted nothing, and reads
// as empty rather than as an error: what it costs is reported by every hook it
// leaves untrusted.
func codexTrustState(path string) (map[string]codexHookState, error) {
	body, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return map[string]codexHookState{}, nil
	case err != nil:
		return nil, err
	}
	var doc codexConfigDoc
	if err := toml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc.Hooks.State, nil
}

// codexHookFiles is every hook file this install wrote for Codex: the
// account-wide one and one per tree enrolled for it. A file that is not there
// is left out rather than reported, `agent rules` and `tree config` owning a
// tree that moved and a file that drifted.
func codexHookFiles(home string, trees []EnrolledTree) []string {
	var files []string
	if account := filepath.Join(home, codexHooksFile); exists(account) {
		files = append(files, account)
	}
	for _, tree := range trees {
		if !slices.Contains(tree.Agents, "codex") {
			continue
		}
		if hooks := filepath.Join(tree.Dir, codexHooksFile); exists(hooks) {
			files = append(files, hooks)
		}
	}
	sort.Strings(files)
	return files
}

// diagnoseCodexTrust reports every faramir hook Codex will not run: one it has
// not been told to trust, one whose identity has moved since it was trusted,
// and one turned off outright.
func diagnoseCodexTrust(report *DoctorReport, opts DoctorOptions) {
	const label = "codex hook trust"
	if opts.AgentUser == "" {
		report.unaskedf(label, 1, "the agent account is not named, so what Codex "+
			"has been told to trust was not asked: run through sudo so SUDO_USER "+
			"carries it, or record the account with `faramir init --agent-user`")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(label, 1, "could not read %s's home, so what Codex has been "+
			"told to trust was not asked", opts.AgentUser)
		return
	}

	trees, err := readEnrolledWhy(opts.ConfigDir)
	// The record is `tree config`'s to fail on. Said here so a report naming
	// only the account-wide hook does not read as a host with no enrolled trees.
	if err != nil {
		report.unaskedf(label, 1, "%s, so only the account-wide hook was examined: "+
			"which trees are enrolled for Codex is unknown", err)
	}
	reportCodexTrust(report, home, trees)
}

// reportCodexTrust is diagnoseCodexTrust against a home already resolved, every
// question being about files under a directory rather than about the passwd
// database.
func reportCodexTrust(report *DoctorReport, home string, trees []EnrolledTree) {
	const label = "codex hook trust"
	files := codexHookFiles(home, trees)
	if len(files) == 0 {
		report.addf(label, StatusNA, "no Codex hook is installed, so nothing here "+
			"has to be trusted")
		return
	}

	configFile := filepath.Join(home, codexConfigFile)
	state, err := codexTrustState(configFile)
	if err != nil {
		if os.IsPermission(err) {
			report.unaskedf(label, 1, "%s could not be read, so what Codex has been "+
				"told to trust was not asked: re-run through sudo", configFile)
			return
		}
		report.addf(label, StatusFailed, "%s does not parse, so whether Codex runs "+
			"the %d hook(s) this install wrote cannot be established: %v",
			configFile, len(files), err)
		return
	}

	var trusted, untrusted, modified, disabled, unread []string
	for _, path := range files {
		hooks, err := codexGuardHooks(path)
		switch {
		case err != nil && os.IsPermission(err):
			report.unaskedf(label, 1, "%s could not be read, so whether Codex runs "+
				"it was not asked: re-run through sudo", path)
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
		report.addf(label, StatusFailed, "%d Codex hook file(s) could not be read, "+
			"so whether Codex runs them cannot be established: %s",
			len(unread), strings.Join(unread, ", "))
	}
	if len(untrusted) > 0 {
		report.addf(label, StatusFailed, "Codex has not been told to trust %d hook(s) "+
			"this install wrote, so it skips them and says nothing: %s. Nothing "+
			"there is refused or routed. Start Codex once in each and answer its "+
			"trust prompt; no flag or config key grants this",
			len(untrusted), strings.Join(untrusted, ", "))
	}
	if len(modified) > 0 {
		report.addf(label, StatusFailed, "Codex trusts a different hook than the %d "+
			"installed here, so it skips what is on disk: %s. A release that "+
			"rewrites the hook does this. Start Codex once in each and trust the "+
			"hook again",
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
		report.addf(label, StatusFailed, "%d Codex hook file(s) are installed and "+
			"none of them carries the guard hook, so there is nothing here for Codex "+
			"to trust and nothing is routed or refused. Re-run the enrolment that "+
			"wrote them", len(files))
		return
	}
	report.addf(label, StatusOK, "Codex trusts the %d hook(s) this install wrote",
		len(trusted))
}
