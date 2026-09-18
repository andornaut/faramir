// Package codextrust reads what Codex has been told to trust: the identity
// Codex computes for a hook, and the state it records against that identity.
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
// new binary. `enrol` in a new checkout writes a hook that starts untrusted for
// the same reason.
//
// Two readers, one answer: `doctor` fails a host whose hooks Codex will not
// run, and an enrolment decides from the same state whether its note still has
// a subject.
package codextrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/andornaut/faramir/internal/agentcfg"
)

// ConfigFile is where Codex records what it has been told to trust, under the
// home of the account that runs it. Written by Codex itself when the operator
// answers its prompt; there is no subcommand or config key that grants this,
// which is why doctor reports it rather than init writing it.
const ConfigFile = ".codex/config.toml"

// trustEvent is PreToolUse as Codex labels it in a state key and in the
// identity it hashes. The only event faramir registers for.
const trustEvent = "pre_tool_use"

// guardMarker identifies faramir's own registration inside a hook file that may
// carry the operator's hooks as well. Both halves of the enrolment run the
// guard in Codex's dialect; the account-wide one adds --deny-only.
const guardMarker = "faramir guard --host codex"

// codexAgent is the target whose note this package answers. Named rather than
// carried on the target: no other agent records what it has been told to trust,
// so there is no second case for a field to hold.
const codexAgent = "codex"

// What Codex fills in for a command hook it parsed, which is what it hashes
// rather than the file's bytes.
const (
	// An absent timeout on every event but SessionEnd and Interrupt, neither of
	// which faramir registers for.
	defaultHookTimeout = 600
	// A context limit equal to the default is dropped from the identity, so the
	// file setting it and the file omitting it hash alike.
	defaultContextLimit = 2500
)

// handler is one hook handler as Codex parses it. Only the keys Codex carries
// into the hashed identity: it ignores what it does not define, and a key
// faramir kept would hash to something Codex never computes.
type handler struct {
	Type                   string  `json:"type"`
	Command                string  `json:"command"`
	Timeout                *int64  `json:"timeout"`
	Async                  bool    `json:"async"`
	StatusMessage          *string `json:"statusMessage"`
	AdditionalContextLimit *int64  `json:"additionalContextLimit"`
}

// matcherGroup is one entry of an event's array: which tools it answers for and
// the handlers that answer.
type matcherGroup struct {
	Matcher *string   `json:"matcher"`
	Hooks   []handler `json:"hooks"`
}

// hooksFileDoc is a hooks.json as Codex reads it. PreToolUse alone: the other
// events are the operator's, and each is trusted on its own key.
type hooksFileDoc struct {
	Hooks struct {
		PreToolUse []matcherGroup `json:"PreToolUse"`
	} `json:"hooks"`
}

// configDoc is the trust state Codex keeps. Every other key in that file is
// Codex's own and is not read here.
type configDoc struct {
	Hooks struct {
		State map[string]HookState `toml:"state"`
	} `toml:"hooks"`
}

// HookState is what Codex records per hook: the identity it was told to trust,
// and whether the hook is turned on at all. A disabled hook does not run
// however well it is trusted.
type HookState struct {
	Enabled     *bool  `toml:"enabled"`
	TrustedHash string `toml:"trusted_hash"`
}

// GuardHook is one faramir registration inside a hook file: the key Codex
// records its trust under, and the identity that key has to hold.
type GuardHook struct {
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

// handlerIdentity is one handler as Codex holds it after parsing, which is what
// goes into the hash. The normalization is Codex's:
//
//   - the Windows command is always unset, so it is never in the identity
//   - an absent timeout becomes 600, and any timeout is at least 1
//   - async is always present, false where the file omits it
//   - a status message and a context limit are carried only where the file sets
//     them, and a context limit equal to the default is dropped
//
// A key the handler does not define is absent rather than null: the identity
// goes through TOML on the way to being hashed, and TOML has no null.
func handlerIdentity(hook handler) map[string]any {
	timeout := int64(defaultHookTimeout)
	if hook.Timeout != nil {
		timeout = *hook.Timeout
	}
	if timeout < 1 {
		timeout = 1
	}
	identity := map[string]any{
		"type":    "command",
		"command": hook.Command,
		"timeout": timeout,
		"async":   hook.Async,
	}
	if hook.StatusMessage != nil {
		identity["statusMessage"] = *hook.StatusMessage
	}
	if hook.AdditionalContextLimit != nil &&
		*hook.AdditionalContextLimit != defaultContextLimit {
		identity["additionalContextLimit"] = *hook.AdditionalContextLimit
	}
	return identity
}

// trustHash is the identity Codex records as trusted: sha256 over the canonical
// JSON of the matcher group carrying this one handler, flattened under the
// event's key label.
//
// The group's own hooks array is replaced by the single handler being hashed,
// so trust is per handler rather than per file: adding a second hook beside
// faramir's leaves faramir's identity alone.
func trustHash(matcher *string, hook handler) (string, error) {
	identity := map[string]any{
		"event_name": trustEvent,
		"hooks":      []any{handlerIdentity(hook)},
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

// GuardHooks is every PreToolUse handler in this file that runs faramir's
// guard, with the key Codex records each one's trust under. The file is merged
// rather than written whole, so the position is read from the file rather than
// assumed: Codex keys a hook by where it sits in the array.
func GuardHooks(path string) ([]GuardHook, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc hooksFileDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var found []GuardHook
	for group, entry := range doc.Hooks.PreToolUse {
		for index, hook := range entry.Hooks {
			if hook.Type != "command" || !strings.Contains(hook.Command, guardMarker) {
				continue
			}
			hash, err := trustHash(entry.Matcher, hook)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			found = append(found, GuardHook{
				Path: path,
				Key:  fmt.Sprintf("%s:%s:%d:%d", path, trustEvent, group, index),
				Hash: hash,
			})
		}
	}
	return found, nil
}

// State is what the agent's Codex config records. A file that is not there is
// the ordinary state of an account that has trusted nothing, and reads as empty
// rather than as an error: what it costs is reported by every hook it leaves
// untrusted.
func State(path string) (map[string]HookState, error) {
	body, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return map[string]HookState{}, nil
	case err != nil:
		return nil, err
	}
	var doc configDoc
	if err := toml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc.Hooks.State, nil
}

// runs reports whether Codex will run the faramir guard hooks written under
// dir, and whether there were any to ask about. A hook is run only where it is
// trusted, still carries the identity that was trusted, and is turned on.
//
// A file that is missing, unreadable, unparsed or carrying no guard hook is not
// examined rather than being counted as untrusted: the note this answers asks
// the operator to trust a hook, and a hook that is not there is `doctor`'s
// finding and another warning's subject.
func runs(state map[string]HookState, dir string) (ran, examined bool) {
	hooks, err := GuardHooks(filepath.Join(dir, agentcfg.CodexHooksFile))
	if err != nil || len(hooks) == 0 {
		return false, false
	}
	for _, hook := range hooks {
		entry, held := state[hook.Key]
		if !held || entry.TrustedHash != hook.Hash ||
			(entry.Enabled != nil && !*entry.Enabled) {
			return false, true
		}
	}
	return true, true
}

// NoteStands reports whether an agent's enrolment note still has a subject.
// Every note but Codex's stands on every run: it describes what a tree or an
// account is, and nothing on disk answers it. Codex's asks the operator to
// trust the hook, and Codex records that, so a run that finds every hook it
// wrote trusted has nothing left to say.
//
// Every scope the run wrote, not one: the account-wide hook and a tree's are
// trusted on separate keys and rendered from separate assets, so a run that
// asked about one of them would go quiet while the other is skipped. The caller
// names the directories it wrote into, home being where Codex keeps what it
// trusts, and asks after it has written them: a hook rewritten since the
// question was put is one the answer does not cover.
//
// The other half of that note, that Codex must run unsandboxed, goes with the
// trust half rather than being said on its own: how Codex was started is not
// something any run can read, and a paragraph printed after every command that
// re-renders the rules is one an operator stops reading.
func NoteStands(agent, home string, dirs ...string) bool {
	// A home that could not be resolved reads nothing: joining an empty one
	// would ask the working directory what Codex trusts, and a tree carrying a
	// .codex/config.toml of its own would answer.
	if agent != codexAgent || home == "" {
		return true
	}
	state, err := State(filepath.Join(home, ConfigFile))
	if err != nil {
		return true
	}
	asked := false
	for _, dir := range dirs {
		ran, examined := runs(state, dir)
		if examined && !ran {
			return true
		}
		asked = asked || examined
	}
	// Nothing to ask about is not an answer: a run that wrote no hook Codex can
	// be told to trust has said nothing about the conditions either.
	return !asked
}
