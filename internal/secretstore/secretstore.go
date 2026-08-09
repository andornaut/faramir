// Package secretstore is the broker's view of the secret values, fetched from
// the keeper.
//
// Two things matter here:
//
//  1. The value set is every secret the keeper knows about, not just the ones
//     injected into the current command.  A secret can reach the output
//     without having been injected (a managed host printing its own
//     configuration will do it), and catching that is the accidental-
//     disclosure guarantee.  So the broker holds the lot, and the redactor is
//     built from all of it.
//  2. The broker never holds the age key.  It cannot decrypt anything; it asks
//     the keeper, which runs as its own uid and serves values only.  Plaintext
//     values live in this process's heap, are never written to disk, and are
//     never placed in an argv.
//
// The keeper is a separate process, so this caches: it reloads on start and
// when a managed file's mtime changes.  The keeper reports those fingerprints
// too, because the store is readable by its group alone and the broker is
// deliberately not in it: reading the ciphertext and asking for the plaintext
// by name are different privileges, and this process only ever needed the
// second.  The cost is that the poll is a socket round trip rather than a stat,
// which is what refresh_interval_sec bounds.
//
// There is no signal that reloads: the file list comes from config.toml, which
// both daemons read once at startup, so a change to it is adopted by restarting
// them rather than by signalling one.
package secretstore

import (
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
	"github.com/andornaut/faramir/internal/secretref"
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
	// retry is set when the keeper could not be reached.  The mtime poll alone
	// would never notice: the files have not changed, only our ability to
	// decrypt them, so without this the value set stays as it was until a file
	// is edited.  On a cold start that set is empty, which
	// means nothing is redacted.
	retry     bool
	checkedAt time.Time

	// Every way a configured file can fail to load, and all of them are
	// failures.  A file that is absent, unreadable, undecryptable, or served by
	// a keeper that did not answer leaves the broker running with values it
	// should have had and does not, so nothing redacts them.  Absent is not a
	// lesser case: a store on a filesystem that is not mounted yet looks exactly
	// like one that was never written, and the safe reading of the two is the
	// same.
	loadErrors []string

	// Held across a refresh-driven reload, not under mu: Reload takes mu
	// itself, and the point is to keep concurrent requests from each starting
	// their own keeper round trip.  The startup Reload is never skipped.
	refreshing atomic.Bool
}

func New(secrets config.SecretsConfig, kc config.KeeperConfig) *Store {
	return &Store{
		config: secrets,
		keeper: kc,
		Policy: redact.EligibilityPolicy{
			MinLength:             secrets.MinLength,
			MinUniqueChars:        secrets.MinUniqueChars,
			MinEntropyBitsPerChar: secrets.MinEntropyBitsPerChar,
		},
		values:  map[string]string{},
		refused: map[string]string{},
	}
}

// Reload re-fetches every value from the keeper.  On startup, and from the
// poll when a managed file has changed.
//
// One round trip: the keeper returns the fingerprints of the files it just
// decrypted alongside the values, so the two cannot describe different moments.
func (s *Store) Reload() {
	// errors names each file the keeper could not stat or could not decrypt,
	// either of which leaves the broker serving fewer values than it is
	// configured for.  Per-file, so one broken file does not blank the set.
	values, state, errors, err := keeperclient.FetchValues(s.keeper.SocketPath)
	if err != nil {
		// Keep the previous value set rather than dropping to empty.  An empty
		// set means nothing is redacted, which is the worst possible response
		// to "the keeper is briefly unreachable".
		//
		// The previous state is kept for the same reason: it is the last thing
		// known to be true, and blanking it would report a file list this
		// process never stopped holding values for.
		s.mu.Lock()
		s.loadErrors = []string{err.Error()}
		s.retry = true
		s.checkedAt = time.Now()
		s.mu.Unlock()
		log.Printf("keeper unreachable, keeping the previous value set "+
			"and retrying on the next request: %v", err)
		return
	}
	// A value the redactor cannot cover is not loaded at all.  Serving it would
	// put it in a child's environment with nothing to catch it on the way out,
	// and the ref is useless to an attacker who cannot obtain the value, so
	// there is nothing here to withhold from the agent.
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
	s.checkedAt = time.Now()
	s.mu.Unlock()

	for _, err := range errors {
		log.Printf("secret load: %s", err)
	}
	// The reason once, then one entry per secret.  Stated per-secret it is
	// repeated as many times as there are short values, and the count belongs
	// here rather than on the summary line below, which would otherwise report
	// the same refusal a second time.
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
// reloads when one changed or when the last attempt could not reach it.
//
// A round trip rather than a stat, because the store is readable by the
// keeper's group and this process is not in it.  The keeper serves this without
// touching the key or execing sops, so it stays the cheap half of the pair:
// what it costs here is a connect, not a decrypt.
//
// refresh_interval_sec bounds how often the poll runs at all.  It may be 0,
// which asks for a check on every request, so the interval alone cannot bound
// the work: a reload is a keeper round trip plus a sops exec per managed file,
// and requests arrive concurrently.  One refresh-driven reload runs at a time
// and the rest return immediately, which also covers the case this has always
// had -- several requests arriving at once just after a file was edited.
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
		// A keeper that cannot say what the files look like cannot say they are
		// unchanged either, and "assume unchanged" is a broker serving a stale
		// set with nothing recording that it might be one.  Reload instead: it
		// fails the same way, keeps the values, and sets retry, which is exactly
		// the state this cannot distinguish itself.
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

// Value returns one secret, or a *secretref.Error.
func (s *Store) Value(ref string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.values[ref]; ok {
		return v, nil
	}
	// Naming the refusal separately: "unknown ref" would send the operator
	// looking for a typo in a ref that is spelled right.
	if reason, ok := s.refused[ref]; ok {
		return "", secretref.Errf("secret %s was refused at load (%s); it cannot be "+
			"redacted, so it is not injectable. Lengthen the value.", ref, reason)
	}
	return "", secretref.Errf("unknown secret ref: %s", ref)
}

// Pairs is every (ref, value) pair: the input to the redactor's value set.
//
// The age key is deliberately absent.  It used to be listed here so that a
// child which printed it got a token instead of the key; no child can obtain
// it any more, so that property now holds by construction rather than by the
// matcher catching it on the way out.
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
	// patterns is what was configured, files is what that named on disk.  Both,
	// because they answer different questions and a glob makes them differ: a
	// store that has not been written yet has patterns and no files, which is
	// how a first install is told apart from one whose store went missing.  This
	// process cannot expand a pattern itself, being outside the store's group,
	// so it reports the entries as written.
	patterns := s.config.Files
	if patterns == nil {
		patterns = []string{}
	}
	return map[string]any{
		"patterns": patterns,
		"files":    files,
		"count":    len(s.values),
		"errors":   errs,
	}
}

// DescribeForOperator is Describe plus the refs refused at load, and why.
//
// Refusing a value stops the broker injecting it; it does not stop the value
// reaching the output some other way, and a refused value is absent from the
// redactor, so it arrives in plaintext when it does.  The list is therefore a
// shortlist of exactly which secrets are never tokenized, which is targeting
// information for the agent and a repair list for the operator.  Only the
// operator gets it.
//
// One snapshot: a reload between the counts and the refused refs would
// otherwise report a set that never existed.
func (s *Store) DescribeForOperator() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.describeLocked()
	refused := make(map[string]string, len(s.refused))
	maps.Copy(refused, s.refused)
	out["not_redactable"] = refused
	return out
}

// LoadErrors is every configured file the broker could not load.  Any entry
// means the redactor is missing values it is configured to hold.
func (s *Store) LoadErrors() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.loadErrors...)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
