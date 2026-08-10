// Package secretstore is the broker's view of the secret values, fetched from
// the keeper.
//
// The value set is every secret the keeper knows, not only the injected ones: a
// managed host can print a credential no command injected.  The broker holds no
// age key and cannot decrypt; plaintext lives in this heap, never on disk and
// never in an argv.
//
// Cached, and reloaded on start and when a managed file's mtime changes.  The
// keeper reports those fingerprints too, since the secrets are readable by
// their group alone, so the poll is a socket round trip rather than a stat --
// refresh_interval_sec bounds it.  Nothing reloads on a signal: the file list
// comes from config.toml, which the daemons read once at startup.
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
	config config.SecretsConfig
	keeper config.KeeperConfig
	Policy redact.EligibilityPolicy

	mu      sync.RWMutex
	values  map[string]string
	refused map[string]string
	state   []keeperclient.FileState
	// retry is set when the keeper could not be reached.  The mtime poll would
	// never notice, since the files have not changed, and on a cold start the
	// value set is empty -- nothing redacted.
	retry     bool
	checkedAt time.Time

	// A configured file that is there and did not load.  The redactor is missing
	// a value it should have, so exec and redact refuse while this is set.
	loadErrors []string

	// A configured entry that named no file.  Kept apart from loadErrors because
	// it is what a first install looks like, though both refuse exec and redact:
	// the daemon logs it and `--check` and `doctor` fail on it.
	unresolved []string

	// Held across a refresh-driven reload, not under mu, which Reload takes
	// itself.  Keeps concurrent requests from each starting a round trip.
	refreshing atomic.Bool
}

func New(secrets config.SecretsConfig, kc config.KeeperConfig) *Store {
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
// sees a managed file change.  One round trip, so the fingerprints and the
// values cannot describe different moments.
func (s *Store) Reload() {
	// Per-file, so one broken file does not blank the set.
	values, state, errors, unresolved, err := keeperclient.FetchValues(s.keeper.SocketPath)
	if err != nil {
		// Keep the previous set rather than dropping to empty, which would
		// redact nothing.  The previous state goes with it, being the last
		// thing known to be true.
		s.mu.Lock()
		s.loadErrors = []string{err.Error()}
		s.unresolved = nil
		s.retry = true
		s.checkedAt = time.Now()
		s.mu.Unlock()
		log.Printf("keeper unreachable, keeping the previous value set "+
			"and retrying on the next request: %v", err)
		return
	}
	// A value the redactor cannot cover is not loaded: serving it would put it
	// in a child's environment with nothing to catch it on the way out.
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
	s.retry = false
	s.loadErrors = errors
	s.unresolved = unresolved
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
	log.Printf("loaded %d secret refs from %d file(s)", len(redactable), len(state))
}

// RefreshIfStale asks the keeper for the managed files' fingerprints, and
// reloads when one changed or the last attempt failed.  A round trip rather
// than a stat, because the secrets are readable by the keeper's group alone;
// the keeper serves it without the key or sops, so it costs a connect.
//
// refresh_interval_sec may be 0, meaning a check on every request, so one
// refresh-driven reload runs at a time and the rest return immediately.
func (s *Store) RefreshIfStale() {
	s.mu.Lock()
	interval := time.Duration(s.config.RefreshIntervalSec) * time.Second
	if interval > 0 && time.Since(s.checkedAt) < interval {
		s.mu.Unlock()
		return
	}
	s.checkedAt = time.Now()
	retry := s.retry
	previous := make(map[keeperclient.FileState]bool, len(s.state))
	for _, st := range s.state {
		previous[st] = true
	}
	s.mu.Unlock()

	if !s.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer s.refreshing.Store(false)

	if retry {
		log.Printf("the last load did not reach the keeper; retrying")
		s.Reload()
		return
	}

	state, _, err := keeperclient.FetchState(s.keeper.SocketPath)
	if err != nil {
		// A keeper that cannot describe the files cannot call them unchanged.
		// Reload instead: it fails the same way, keeps the values, and sets
		// retry.
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

// Refs returns names only.  Safe to hand to the agent.
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

// Pairs is every (ref, value) pair: the input to the redactor's value set.  The
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

// Describe is a loaded-state summary.  Safe for the agent-facing wire.
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
	// patterns is what was configured, files what it named on disk.  A glob
	// makes them differ, which is how a first install is told apart from secrets
	// that went missing.  This process cannot expand a pattern itself.
	patterns := s.config.Files
	if patterns == nil {
		patterns = []string{}
	}
	absent := s.unresolved
	if absent == nil {
		absent = []string{}
	}
	return map[string]any{
		"patterns":   patterns,
		"files":      files,
		"count":      len(s.values),
		"errors":     errs,
		"unresolved": absent,
	}
}

// DescribeForOperator is Describe plus the refs refused at load, and why.  A
// refused value is absent from the redactor, so the list names exactly which
// secrets are never tokenized: a repair list for the operator, targeting
// information for the agent, and operator-only for that reason.
//
// One snapshot, or a reload in between would report a set that never existed.
func (s *Store) DescribeForOperator() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.describeLocked()
	refused := make(map[string]string, len(s.refused))
	maps.Copy(refused, s.refused)
	out["not_redactable"] = refused
	return out
}

// LoadErrors is every configured file the broker could not load, each one a
// value the redactor is missing.
func (s *Store) LoadErrors() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.loadErrors...)
}

// Unresolved is the configured entries that named no file.  Apart from
// LoadErrors because it is what a first install looks like: the daemon starts
// and says so, while `--check` and `doctor` fail on it.
func (s *Store) Unresolved() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.unresolved...)
}

// Count is how many values the redactor holds.  Zero means nothing is injected
// and nothing is redacted, whatever the reason.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}

// Unreadable reports why the broker cannot promise redaction, or "" when it
// can.  The gate on both exec and redact: a brokered command's output is
// redacted against this same set, so what makes one unsafe makes the other
// unsafe.
//
// The risk is output holding a managed secret the redactor does not have, so
// the test is whether a managed file exists whose contents went unread: at least
// one file matched, and every matched file loaded.  How many secrets came out of
// them does not enter into it, an empty file holding nothing to miss.  A ref no
// file defines is answered by unknown_secret.
//
// Called per request, since a reload can lose a file at any time.
//
// A keeper that could not be reached is the exception, but only once a set has
// loaded: what is kept then is the last thing known to be true, unconfirmed
// rather than short.  A cold start has nothing to keep, so it refuses.
func (s *Store) Unreadable() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch {
	case s.retry && len(s.state) > 0:
		return ""
	case s.retry:
		return "the keeper could not be reached and no value set was ever loaded: " +
			strings.Join(s.loadErrors, "; ")
	case len(s.loadErrors) > 0:
		return "a managed file did not load, so what is in it went unread: " +
			strings.Join(s.loadErrors, "; ")
	case len(s.state) > 0:
		return ""
	case len(s.config.Files) == 0:
		return "no [secrets] files are configured"
	}
	return "no managed file was found: " + strings.Join(s.unresolved, "; ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
