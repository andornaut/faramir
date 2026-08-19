// Package secretstore is the broker's view of the secret values, fetched from
// the keeper.
//
// The value set is every secret the keeper manages, not only the injected ones:
// a managed host can print a credential no command injected. The broker holds
// no age key and cannot decrypt; plaintext lives in this heap, never on disk
// and never in an argv.
//
// Cached, and reloaded on start and when a managed file's mtime changes. The
// keeper reports those fingerprints too, the secrets being readable by their
// group alone, so the poll is a socket round trip bounded by min_refresh_sec.
// Nothing reloads on a signal: the file list comes from config.toml, which the
// daemons read once at startup.
package secretstore

import (
	"fmt"
	"log"
	"maps"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeperclient"
	"github.com/andornaut/faramir/internal/redact"
)

// Store is a concurrency-safe, mtime-refreshed view of every managed secret.
type Store struct {
	config config.SecretConfig
	keeper config.KeeperConfig
	Policy redact.EligibilityPolicy

	mu      sync.RWMutex
	values  map[string]string
	refused map[string]string
	state   []keeperclient.FileState
	// linkState is the same fingerprint for the [[secret.link]] files. Kept
	// apart from state because the broker stats these itself, they being the
	// operator's own files and reachable from this uid.
	linkState []keeperclient.FileState
	// retry is set when the keeper could not be reached: the mtime poll would
	// never notice, the files not having changed.
	retry     bool
	checkedAt time.Time

	// A configured file that is there and did not load. The redactor is missing
	// a value it should have, so exec and redact refuse while this is set.
	loadErrors []string

	// A configured entry that named no file. Kept apart from loadErrors because
	// it is what a first install looks like, though both refuse exec and
	// redact.
	unresolvedPatterns []string

	// Held across a refresh-driven reload, not under mu, which Reload takes
	// itself. Keeps concurrent requests from each starting a round trip.
	refreshing atomic.Bool
}

func New(secrets config.SecretConfig, kc config.KeeperConfig) *Store {
	return &Store{
		config: secrets,
		keeper: kc,
		Policy: redact.EligibilityPolicy{
			MinLength: secrets.MinLength,
		},
		values:  map[string]string{},
		refused: map[string]string{},
	}
}

// Reload re-fetches every value from the keeper, on startup and when the poll
// sees a managed file change. One round trip, so the fingerprints and the
// values cannot describe different moments.
func (s *Store) Reload() {
	// Per-file, so one broken file does not blank the set.
	values, state, errors, unresolved, err := keeperclient.FetchValues(s.keeper.SocketPath)
	if err != nil {
		// Keep the previous set rather than dropping to empty, which would redact
		// nothing. The linked values are kept with it and not re-read: half a set
		// refreshed against a keeper that could not answer is a set that never
		// existed on disk.
		s.mu.Lock()
		s.loadErrors = []string{err.Error()}
		s.unresolvedPatterns = nil
		s.retry = true
		s.checkedAt = time.Now()
		s.mu.Unlock()
		log.Printf("keeper unreachable, keeping the previous value set "+
			"and retrying on the next request: %v", err)
		return
	}
	// The links, read here rather than asked of the keeper. Merged before the
	// length gate, so a linked value is held to what a managed one is.
	linkValues, linkState, linkErrors, linkUnresolved := loadLinks(s.config.Links)
	for _, ref := range sortedKeys(linkValues) {
		// Refused rather than resolved: a link shadowing a managed value would
		// leave one of them rotating with nothing reading it.
		if _, ok := values[ref]; ok {
			linkErrors = append(linkErrors, fmt.Sprintf("%s: a [[secret.link]] entry "+
				"claims a ref the managed store already defines; one of the two is "+
				"then rotated with nothing reading it, so rename the link or remove "+
				"the managed value", ref))
			continue
		}
		values[ref] = linkValues[ref]
	}
	errors = append(errors, linkErrors...)
	unresolved = append(unresolved, linkUnresolved...)

	// A value the redactor cannot cover is not loaded: serving it would put it in
	// a child's environment with nothing to catch it on the way out.
	redactable := map[string]string{}
	refused := map[string]string{}
	for ref, value := range values {
		if reason := s.Policy.Check(value); reason == "" {
			redactable[ref] = value
		} else {
			refused[ref] = reason
		}
	}

	s.mu.Lock()
	s.values = redactable
	s.refused = refused
	s.state = state
	s.linkState = linkState
	s.retry = false
	s.loadErrors = errors
	s.unresolvedPatterns = unresolved
	s.checkedAt = time.Now()
	s.mu.Unlock()

	for _, err := range errors {
		log.Printf("secret load: %s", err)
	}
	for _, entry := range unresolved {
		log.Printf("secret entry named nothing: %s", entry)
	}
	// The reason once, then one entry per secret.
	if len(refused) > 0 {
		entries := make([]string, 0, len(refused))
		for _, ref := range sortedKeys(refused) {
			entries = append(entries, ref+" ("+refused[ref]+")")
		}
		log.Printf("%d of %d secrets refused as not redactable, so they are never "+
			"injected; lengthen them: %s",
			len(refused), len(redactable)+len(refused), strings.Join(entries, ", "))
	}
	log.Printf("loaded %d vault refs from %d file(s)", len(redactable), len(state))
}

// RefreshIfStale asks the keeper for the managed files' fingerprints, and
// reloads when one changed or the last attempt failed. A round trip rather
// than a stat, the secrets being readable by the keeper's group alone; the
// keeper serves it without the key or sops, so it costs a connect.
//
// One refresh-driven reload runs at a time and the rest return immediately.
func (s *Store) RefreshIfStale() {
	// One refresh at a time, whichever half triggers it. A caller that arrives
	// while another is working returns rather than queueing behind it.
	if !s.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer s.refreshing.Store(false)

	// The links, on every request and not on the interval: they are the
	// operator's own files and this uid can stat them, so the cost is a stat per
	// linked file. The interval bounds the round trip, and applying it here
	// would leave a credential another tool has just rotated missing from the
	// redactor for up to min_refresh_sec.
	s.mu.Lock()
	retrying := s.retry
	previousLinks := make(map[keeperclient.FileState]bool, len(s.linkState))
	for _, st := range s.linkState {
		previousLinks[st] = true
	}
	s.mu.Unlock()

	// Not while a load is outstanding: a failed load records no link state, so
	// the comparison below would call every request a change. The
	// interval-gated retry covers it.
	if retrying {
		s.retryUnderTheInterval()
		return
	}

	currentLinks := make(map[keeperclient.FileState]bool, len(s.config.Links))
	for _, st := range statLinks(s.config.Links) {
		currentLinks[st] = true
	}
	if !sameSet(previousLinks, currentLinks) {
		log.Printf("a linked secret file changed on disk; reloading")
		s.Reload()
		return
	}

	s.keeperIfStale()
}

// retryUnderTheInterval re-loads a set that never loaded, no more often than
// the interval allows.
func (s *Store) retryUnderTheInterval() {
	if !s.intervalElapsed() {
		return
	}
	log.Printf("the last load did not reach the keeper; retrying")
	s.Reload()
}

// intervalElapsed reports whether the keeper may be asked again, and records
// the attempt when it may.
func (s *Store) intervalElapsed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	interval := time.Duration(s.config.MinRefreshSec) * time.Second
	if interval > 0 && time.Since(s.checkedAt) < interval {
		return false
	}
	s.checkedAt = time.Now()
	return true
}

// keeperIfStale asks the keeper whether a managed file changed, no more often
// than the interval allows. This one is the socket round trip
// min_refresh_sec exists to bound.
func (s *Store) keeperIfStale() {
	if !s.intervalElapsed() {
		return
	}
	s.mu.Lock()
	previous := make(map[keeperclient.FileState]bool, len(s.state))
	for _, st := range s.state {
		previous[st] = true
	}
	s.mu.Unlock()

	state, _, err := keeperclient.FetchState(s.keeper.SocketPath)
	if err != nil {
		// A keeper that cannot describe the files cannot call them unchanged.
		// Reload fails the same way, keeps the values, and sets retry.
		s.Reload()
		return
	}
	current := make(map[keeperclient.FileState]bool, len(state))
	for _, st := range state {
		current[st] = true
	}
	if !sameSet(previous, current) {
		log.Printf("managed secret file changed on disk; reloading")
		s.Reload()
	}
}

func sameSet(a, b map[keeperclient.FileState]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// Refs returns names only. Safe to hand to the agent.
func (s *Store) Refs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedKeys(s.values)
}

// Value returns one secret.
func (s *Store) Value(ref string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.values[ref]; ok {
		return v, nil
	}
	// Named separately, so a refused ref does not read as a typo.
	if reason, ok := s.refused[ref]; ok {
		return "", fmt.Errorf("secret %s was refused at load (%s); it cannot be "+
			"redacted, so it is not injectable -- lengthen the value", ref, reason)
	}
	return "", fmt.Errorf("unknown secret ref: %s", ref)
}

// Pairs is every (ref, value) pair: the input to the redactor's value set. The
// age key is absent, no child being able to obtain it.
func (s *Store) Pairs() []redact.Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]redact.Secret, 0, len(s.values))
	for _, ref := range sortedKeys(s.values) {
		out = append(out, redact.Secret{Ref: ref, Value: s.values[ref]})
	}
	return out
}

// Describe is a loaded-state summary. Safe for the agent-facing wire.
func (s *Store) Describe() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.describeLocked()
}

func (s *Store) describeLocked() map[string]any {
	files := make([]string, 0, len(s.state))
	for _, st := range s.state {
		files = append(files, st.Path)
	}
	errs := s.loadErrors
	if errs == nil {
		errs = []string{}
	}
	// patterns is what was configured, files what it named on disk. A glob makes
	// them differ, which is how a first install is told apart from secrets that
	// went missing.
	patterns := s.config.Patterns
	if patterns == nil {
		patterns = []string{}
	}
	absent := s.unresolvedPatterns
	if absent == nil {
		absent = []string{}
	}
	return map[string]any{
		"patterns":            patterns,
		"files":               files,
		"count":               len(s.values),
		"errors":              errs,
		"unresolved_patterns": absent,
		// A count, not the paths: a linked file is one of the operator's own,
		// refused to the agent's file tools, so naming it here would hand over the
		// location of a credential. DescribeForOperator carries the paths.
		"links": len(s.config.Links),
	}
}

// DescribeForOperator is Describe plus the refs refused at load, and why. A
// refused value is absent from the redactor, so the list names which secrets
// are never tokenized: a repair list for the operator, targeting information
// for the agent, and operator-only for that reason. One snapshot, or a reload
// in between would report a set that never existed.
func (s *Store) DescribeForOperator() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.describeLocked()
	refused := make(map[string]string, len(s.refused))
	maps.Copy(refused, s.refused)
	out["not_redactable"] = refused
	// Ref to file, so `--check` and doctor can say which link is broken and where
	// to fix it. Operator-only for the reason describeLocked gives.
	linked := make(map[string]string, len(s.config.Links))
	for _, link := range s.config.Links {
		linked[link.Ref] = link.Path
	}
	out["linked_files"] = linked
	return out
}

// LoadErrors is every configured file the broker could not load, each one a
// value the redactor is missing.
func (s *Store) LoadErrors() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.loadErrors...)
}

// UnresolvedPatterns is the configured entries that named no file. Apart from
// LoadErrors because it is what a first install looks like: the daemon starts
// and says so, while `--check` and `doctor` fail on it.
func (s *Store) UnresolvedPatterns() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.unresolvedPatterns...)
}

// Count is how many values the redactor holds. Zero means nothing is injected
// and nothing is redacted, whatever the reason.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}

// Unreadable reports why the broker cannot promise redaction, or "" when it
// can. The gate on both exec and redact, a brokered command's output being
// redacted against this same set.
//
// The risk is output holding a managed secret the redactor does not have, so
// the test is whether a managed file exists whose contents went unread: at
// least one file matched, and every matched file loaded. How many secrets came
// out of them does not enter into it. Called per request, a reload being able
// to lose a file at any time.
//
// A keeper that could not be reached is the exception, but only once a set has
// loaded: what is kept then is unconfirmed rather than short.
func (s *Store) Unreadable() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch {
	// linkState as well as state: an install whose only secrets are linked holds
	// its whole value set without the keeper contributing anything.
	case s.retry && (len(s.state) > 0 || len(s.linkState) > 0):
		return ""
	case s.retry:
		return "the keeper could not be reached and no value set was ever loaded: " +
			strings.Join(s.loadErrors, "; ")
	case len(s.loadErrors) > 0:
		return "a managed file did not load, so what is in it went unread: " +
			strings.Join(s.loadErrors, "; ")
	case len(s.state) > 0, len(s.linkState) > 0:
		return ""
	case len(s.config.Patterns) == 0 && len(s.config.Links) == 0:
		return "the store is empty and no [[secret.link]] entries are configured"
	}
	return "no managed file was found: " + strings.Join(s.unresolvedPatterns, "; ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
