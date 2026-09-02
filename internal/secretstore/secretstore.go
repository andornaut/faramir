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
// group alone, so the poll is a socket round trip bounded by the refresh interval.
// Nothing reloads on a signal: the file list comes from config.toml, which the
// daemons read once at startup.
package secretstore

import (
	goerrors "errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/secretref"
)

// Store is a concurrency-safe, mtime-refreshed view of every managed secret.
type Store struct {
	config config.SecretConfig
	keeper config.KeeperConfig
	Policy redact.EligibilityPolicy

	mu      sync.RWMutex
	values  map[string]string
	refused map[string]string
	state   []fileState
	// linkState is the same fingerprint for the [[secret.link]] files. Kept
	// apart from state because the broker stats these itself, they being the
	// operator's own files and reachable from this uid.
	linkState []fileState
	// unconfirmed is set when the last load did not reach the keeper, so the
	// value set held here was never checked against what is on disk. Two things
	// read it. Unreadable tells an unconfirmed set apart from one that never
	// loaded at all: the first serves, the second refuses. RefreshIfStale sends
	// an unconfirmed set to the interval instead of the fingerprint comparison,
	// which would call every request a change, a failed load having recorded no
	// fingerprints to compare against.
	unconfirmed bool
	checkedAt   time.Time

	// A managed file that is there and did not load. The redactor is missing
	// values it should have and cannot name which, one file holding any number of
	// refs, so exec and redact refuse while this is set.
	loadErrors []string

	// Refs more than one managed file defined; see valueSet.
	shadowedRefs map[string]string
	// The value set compiled into a matcher, rebuilt when the values are. The
	// broker takes several redactors for one request and the set changes only
	// here, so compiling per request cost every command the size of the set:
	// `faramir run -- true` took 35 ms on a host with 256 refs and 2 ms on one
	// with a single ref, all of it building this.
	compiled *redact.Values
	// A configured pattern that named no file. Kept apart from loadErrors because
	// it is what a first install looks like, though both refuse exec and
	// redact.
	unresolvedPatterns []string

	// A [[secret.link]] entry that did not load, by ref, with the reason a caller
	// asking for that ref is given. It refuses that ref and nothing else: a link
	// is one ref by construction, so what is missing is known by name and the
	// rest of the set is unaffected. linkDetail is the same failures with their
	// paths, for the log and the operator's report.
	degradedLinks map[string]string
	linkDetail    []string

	// Held across a refresh-driven reload, not under mu, which Reload takes
	// itself. Keeps concurrent requests from each starting a round trip.
	// refreshing serialises reloads: one runs at a time and the callers differ in
	// what they do about it. A buffered channel rather than a flag, so the forced
	// path can wait for the one in flight with a deadline instead of spinning on
	// a compare-and-swap, which held a connection goroutine through a shutdown.
	refreshing chan struct{}
}

func New(secrets config.SecretConfig, kc config.KeeperConfig) *Store {
	return &Store{
		config: secrets,
		keeper: kc,
		Policy: redact.EligibilityPolicy{
			MinLength: secrets.MinLength,
		},
		values:        map[string]string{},
		refused:       map[string]string{},
		degradedLinks: map[string]string{},
		refreshing:    make(chan struct{}, 1),
	}
}

// Reload re-fetches every value from the keeper, on startup and when the poll
// sees a managed file change. One round trip, so the fingerprints and the
// values cannot describe different moments.
func (s *Store) Reload() {
	// Per-file, so one broken file does not blank the set.
	loaded, err := fetchValues(s.keeper.SocketPath)
	values, state := loaded.Values, loaded.State
	errors, unresolved := loaded.Errors, loaded.UnresolvedPatterns
	if goerrors.Is(err, errReplyTooLarge) {
		// Not marked unconfirmed, which would re-load on the interval: this
		// failure is permanent, so that would re-decrypt the whole store on every
		// refresh and never succeed. Recorded as a load failure instead, which is
		// what refuses: a managed file was read and its values did not reach the
		// redactor.
		s.mu.Lock()
		s.loadErrors = []string{err.Error()}
		s.unresolvedPatterns = nil
		s.unconfirmed = false
		s.checkedAt = time.Now()
		s.mu.Unlock()
		log.Printf("refusing exec and redact: %v", err)
		return
	}
	if err != nil {
		// Keep the previous set rather than dropping to empty, which would redact
		// nothing. The linked values are kept with it and not re-read: half a set
		// refreshed against a keeper that could not answer is a set that never
		// existed on disk.
		s.mu.Lock()
		s.loadErrors = []string{err.Error()}
		s.unresolvedPatterns = nil
		s.unconfirmed = true
		s.checkedAt = time.Now()
		s.mu.Unlock()
		log.Printf("keeper unreachable, keeping the previous value set "+
			"unconfirmed and loading again on the next request past the "+
			"refresh interval: %v", err)
		return
	}
	// The links, read here rather than asked of the keeper. Merged before the
	// length gate, so a linked value is held to what a managed one is.
	linkValues, linkState, degradedLinks, linkDetail := loadLinks(s.config.Links)
	for _, ref := range sortedKeys(linkValues) {
		// Blocked rather than resolved: a link shadowing a managed value would
		// leave one of them rotating with nothing reading it.
		if _, ok := values[ref]; ok {
			// Not a degraded ref: this one is answered, by the managed store. What is
			// wrong is that a second file holds a value for the same name, and that
			// value is on disk and not in the redactor, so a fault of the managed
			// store's kind and refused the same way.
			errors = append(errors, fmt.Sprintf("%s: a [[secret.link]] entry claims a "+
				"ref the managed store already defines. The managed value is what "+
				"callers get, and the linked file holds a second value for that name "+
				"which nothing reads and nothing redacts; one of the two is then "+
				"rotated with nothing reading it, so rename the link or remove the "+
				"managed value", ref))
			continue
		}
		values[ref] = linkValues[ref]
	}

	// A value the redactor cannot cover is not loaded: serving it would put it in
	// a child's environment with nothing to catch it on the way out. A ref no
	// caller could spell goes the same way: a name that reaches `faramir refs`
	// and then is refused by every path that injects it is one the agent is
	// offered and cannot use. A [[secret.link]] ref is held to this at config
	// load; a key out of a managed file arrives here instead.
	redactable := map[string]string{}
	refused := map[string]string{}
	for ref, value := range values {
		if !secretref.Valid(ref) {
			refused[ref] = "is not a name a faramir:// reference can carry, " +
				"which is letters, digits, and then any of . _ - /"
			continue
		}
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
	s.unconfirmed = false
	s.loadErrors = errors
	s.unresolvedPatterns = unresolved
	s.shadowedRefs = loaded.ShadowedRefs
	// Under the same lock as the values it is built from, so a reader never sees
	// a matcher describing a set that is no longer there.
	s.compiled = redact.NewValues(pairsOf(redactable), s.Policy)
	s.degradedLinks = degradedLinks
	s.linkDetail = linkDetail
	s.checkedAt = time.Now()
	s.mu.Unlock()

	for _, err := range errors {
		log.Printf("secret load: %s", err)
	}
	// Logged as what they are: one ref that answers nothing, on a broker that
	// goes on serving every other one.
	for _, err := range linkDetail {
		log.Printf("linked secret did not load, so that ref is refused: %s", err)
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
			"injected; the reason beside each says what to fix: %s",
			len(refused), len(redactable)+len(refused), strings.Join(entries, ", "))
	}
	log.Printf("loaded %d vault refs from %d file(s)", len(redactable), len(state))
}

// Refresh re-reads the whole set now, whatever the interval says. For a writer
// of the managed store that knows it just changed one: `faramir vault` calls it
// so a rotated value is in the redactor before the command that rotated it has
// returned, rather than up to the refresh interval later. Everything else
// arrives through RefreshIfStale.
func (s *Store) Refresh(wait time.Duration) bool {
	// Waits for a refresh already under way rather than returning on its
	// account. One that started before the caller's write took its fingerprints
	// from before it too, so it will find nothing changed and return, and
	// treating that as the re-read this promises would leave the new value
	// outside the redactor while the command that wrote it says otherwise.
	//
	// Bounded, and it says whether it got in. A reload of a large store execs
	// sops once per file and may run for minutes, and a caller that waited on it
	// without a limit would be a connection goroutine the broker cannot shut
	// down. Answering false is the honest outcome there: the caller reports what
	// it could not promise rather than promising it anyway.
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case s.refreshing <- struct{}{}:
	case <-timer.C:
		return false
	}
	defer func() { <-s.refreshing }()
	s.Reload()
	return true
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
	select {
	case s.refreshing <- struct{}{}:
	default:
		return
	}
	defer func() { <-s.refreshing }()

	// The links, on every request and not on the interval: they are the
	// operator's own files and this uid can stat them, so the cost is a stat per
	// linked file. The interval bounds the round trip, and applying it here
	// would leave a credential another tool has just rotated missing from the
	// redactor for up to the refresh interval.
	s.mu.Lock()
	unconfirmed := s.unconfirmed
	previousLinks := make(map[fileState]bool, len(s.linkState))
	for _, st := range s.linkState {
		previousLinks[st] = true
	}
	s.mu.Unlock()

	// An unconfirmed set skips the comparison below: a failed load records no
	// link state, so every request would compare against nothing and read as a
	// change. Reloading on the interval is what covers it.
	if unconfirmed {
		s.reloadUnderTheInterval()
		return
	}

	currentLinks := make(map[fileState]bool, len(s.config.Links))
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

// reloadUnderTheInterval re-loads a set whose last load did not reach the
// keeper, no more often than the interval allows. This is what recovers a
// broker that started before the keeper's socket was bound, with no restart
// and no file having changed.
func (s *Store) reloadUnderTheInterval() {
	if !s.intervalElapsed() {
		return
	}
	log.Printf("the last load did not reach the keeper; loading again")
	s.Reload()
}

// intervalElapsed reports whether the keeper may be asked again, and records
// the attempt when it may.
func (s *Store) intervalElapsed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	interval := time.Duration(config.MinRefreshSec) * time.Second
	if interval > 0 && time.Since(s.checkedAt) < interval {
		return false
	}
	s.checkedAt = time.Now()
	return true
}

// keeperIfStale asks the keeper whether a managed file changed, no more often
// than the interval allows. This one is the socket round trip
// config.MinRefreshSec exists to bound.
func (s *Store) keeperIfStale() {
	if !s.intervalElapsed() {
		return
	}
	s.mu.Lock()
	previous := make(map[fileState]bool, len(s.state))
	for _, st := range s.state {
		previous[st] = true
	}
	s.mu.Unlock()

	state, _, err := fetchState(s.keeper.SocketPath)
	if err != nil {
		// A keeper that cannot describe the files cannot call them unchanged.
		// Reload fails the same way, keeps the values, and marks them unconfirmed.
		s.Reload()
		return
	}
	current := make(map[fileState]bool, len(state))
	for _, st := range state {
		current[st] = true
	}
	if !sameSet(previous, current) {
		log.Printf("managed secret file changed on disk; reloading")
		s.Reload()
	}
}

func sameSet(a, b map[fileState]bool) bool {
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
	// Named separately, so a refused ref does not read as a typo. The reason
	// carries the remedy: what to do about a value too short to redact is not
	// what to do about one too large to inject, and a fixed "lengthen the value"
	// was advice for one of them given to both.
	if reason, ok := s.refused[ref]; ok {
		return "", fmt.Errorf("secret %s was refused at load: %s. It is neither "+
			"injected nor redacted; `sudo faramir vault edit` is where it is fixed",
			ref, reason)
	}
	// Nor does a link that did not load. The path is left out deliberately: it is
	// the location of a credential, and this answer reaches the caller.
	if reason, ok := s.degradedLinks[ref]; ok {
		return "", fmt.Errorf("secret %s is linked and did not load: %s. Every "+
			"other ref is unaffected; `faramir status` names it and `sudo faramir "+
			"doctor` says what to do about it", ref, reason)
	}
	// The remedy, which the two refusals above carry and this one did not: a
	// well-formed ref that names nothing is a name the caller has to look up,
	// and every other spelling error is answered by a message that says where.
	return "", fmt.Errorf("unknown secret ref: %s; `faramir refs` lists what "+
		"this host holds", ref)
}

// Redactor is a redactor over the current value set, sharing the compiled
// matcher rather than building one. Every caller that redacts should take one
// from here.
func (s *Store) Redactor() *redact.Redactor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.compiled == nil {
		// A store that has not loaded yet. It serves nothing, so there is nothing
		// to match; building an empty set per call costs nothing worth caching.
		return redact.New(nil, s.Policy)
	}
	return s.compiled.Redactor()
}

// pairsOf is pairs over a map the caller already holds, for the compile above:
// pairs takes the read lock, which Reload holds for writing.
func pairsOf(values map[string]string) []redact.Secret {
	out := make([]redact.Secret, 0, len(values))
	for _, ref := range sortedKeys(values) {
		out = append(out, redact.Secret{Ref: ref, Value: values[ref]})
	}
	return out
}

// pairs is every (ref, value) pair: the input to the redactor's value set. The
// age key is absent, no child being able to obtain it.
func (s *Store) pairs() []redact.Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]redact.Secret, 0, len(s.values))
	for _, ref := range sortedKeys(s.values) {
		out = append(out, redact.Secret{Ref: ref, Value: s.values[ref]})
	}
	return out
}
