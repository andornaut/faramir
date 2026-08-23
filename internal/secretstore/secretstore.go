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
	goerrors "errors"
	"fmt"
	"log"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeperclient"
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
	state   []keeperclient.FileState
	// linkState is the same fingerprint for the [[secret.link]] files. Kept
	// apart from state because the broker stats these itself, they being the
	// operator's own files and reachable from this uid.
	linkState []keeperclient.FileState
	// retry is set when the keeper could not be reached: the mtime poll would
	// never notice, the files not having changed.
	retry     bool
	checkedAt time.Time

	// A managed file that is there and did not load. The redactor is missing
	// values it should have and cannot name which, one file holding any number of
	// refs, so exec and redact refuse while this is set.
	loadErrors []string

	// Refs more than one managed file defined; see keeperclient.Loaded.
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
	loaded, err := keeperclient.FetchValues(s.keeper.SocketPath)
	values, state := loaded.Values, loaded.State
	errors, unresolved := loaded.Errors, loaded.UnresolvedPatterns
	if goerrors.Is(err, keeperclient.ErrReplyTooLarge) {
		// Permanent, so not the retry path below: retrying re-decrypts the whole
		// store on every refresh and never succeeds, while the values that could
		// not be carried are absent from the redactor and the broker goes on
		// serving against the set it happened to have. Recorded as a load failure,
		// which is what refuses: a managed file was read and its values did not
		// reach the redactor.
		s.mu.Lock()
		s.loadErrors = []string{err.Error()}
		s.unresolvedPatterns = nil
		s.retry = false
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
		s.retry = true
		s.checkedAt = time.Now()
		s.mu.Unlock()
		log.Printf("keeper unreachable, keeping the previous value set "+
			"and retrying on the next request: %v", err)
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
	s.retry = false
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
// returned, rather than up to [secret] min_refresh_sec later. Everything else
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
	// Nor does a link that did not load. The path is left out deliberately: it is
	// the location of a credential, and this answer reaches the caller.
	if reason, ok := s.degradedLinks[ref]; ok {
		return "", fmt.Errorf("secret %s is linked and did not load: %s. Every "+
			"other ref is unaffected; `faramir status` names it and `sudo faramir "+
			"doctor` says what to do about it", ref, reason)
	}
	return "", fmt.Errorf("unknown secret ref: %s", ref)
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

// pairsOf is Pairs over a map the caller already holds, for the compile above:
// Pairs takes the read lock, which Reload holds for writing.
func pairsOf(values map[string]string) []redact.Secret {
	out := make([]redact.Secret, 0, len(values))
	for _, ref := range sortedKeys(values) {
		out = append(out, redact.Secret{Ref: ref, Value: values[ref]})
	}
	return out
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
		// Refs and reasons, no paths, to the same rule. A degraded ref is not one
		// the refs op lists, that being the loaded ones, but it is a name the agent
		// can already read out of `faramir link ls` and is given verbatim the
		// moment it asks for the ref. Where the file lives is what stays out.
		"degraded_links": maps.Clone(s.degradedLinks),
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
	// The refs two managed files both defined, with the files named. Same kind of
	// missing as not_redactable: the value exists on disk, one of the two is in
	// no redactor, and neither is a file that would not open. Operator-only for
	// the reason describeLocked gives, and a repair list rather than a
	// diagnostic.
	shadowed := make(map[string]string, len(s.shadowedRefs))
	maps.Copy(shadowed, s.shadowedRefs)
	out["shadowed_refs"] = shadowed
	// Ref to file, so `--check` and doctor can say which link is broken and where
	// to fix it. Operator-only for the reason describeLocked gives.
	linked := make(map[string]string, len(s.config.Links))
	for _, link := range s.config.Links {
		linked[link.Ref] = link.Path
	}
	out["linked_files"] = linked
	// The same failures with their paths, which the agent-facing summary leaves
	// out.
	out["degraded_link_detail"] = append([]string{}, s.linkDetail...)
	return out
}

// DegradedLinks is the [[secret.link]] entries that did not load, by ref, with
// the reason each is refused. Empty when every link resolved.
//
// Not part of Unreadable: what is missing is known by name, so it refuses that
// ref and leaves the broker serving. `faramir status` and `sudo faramir doctor`
// are what fail on it, this being a fault nothing else would surface until a
// command asked for the ref.
func (s *Store) DegradedLinks() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return maps.Clone(s.degradedLinks)
}

// Degraded reports why this store is not doing the whole job the config asks
// of it, or "" when it is. Every state that leaves a configured ref not working
// or a configured value uncovered, in one question, for the two commands whose
// exit code answers it.
//
// Wider than Unreadable, which is the gate on serving. A ref too short to cover
// and a link that did not load both leave the broker serving, and both mean a
// name the operator configured does not answer; a host in either state is not
// the host its config describes.
//
// Names refs, never values and never the paths behind a link: this reaches the
// agent through `faramir status`.
func (s *Store) Degraded() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var why []string
	if len(s.degradedLinks) > 0 {
		why = append(why, fmt.Sprintf("%d linked ref(s) did not load: %s",
			len(s.degradedLinks), strings.Join(sortedKeys(s.degradedLinks), ", ")))
	}
	if len(s.refused) > 0 {
		// Named, never the reason each carries: length is one of them and the
		// operator-facing surfaces are where the rest are said.
		why = append(why, fmt.Sprintf("%d ref(s) cannot be redacted, so they "+
			"are never injected: %s", len(s.refused), strings.Join(sortedKeys(s.refused), ", ")))
	}
	// A ref two managed files define differently: the loser is on disk, in no
	// redactor, and a command that prints it prints it. The same consequence as
	// a refused ref, so it is counted the same way. Named, never the files that
	// define it, which is what --check adds for the operator.
	if len(s.shadowedRefs) > 0 {
		why = append(why, fmt.Sprintf("%d ref(s) are defined with different "+
			"values by more than one managed file, so one value is in no "+
			"redactor: %s", len(s.shadowedRefs), strings.Join(sortedKeys(s.shadowedRefs), ", ")))
	}
	if len(s.loadErrors) > 0 {
		// Counted, not quoted: a load error carries the path of a managed file.
		why = append(why, fmt.Sprintf("%d managed file(s) did not load", len(s.loadErrors)))
	}
	// A configured entry that named no file is not counted, matching the
	// operator-facing report: a host that manages no credentials is doing its
	// job, and there is no value for output to carry that the redactor lacks.
	// What does count is a file that was found and did not load, above.
	return strings.Join(why, "; ")
}

// LoadErrors is every configured file the broker could not load, each one a
// value the redactor is missing.
func (s *Store) LoadErrors() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.loadErrors...)
}

// ShadowedRefs is the refs more than one managed file defines with different
// values, by ref and by which files define them. The loser is in no redactor,
// so this names a value on this host that a command could print in the clear.
func (s *Store) ShadowedRefs() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return maps.Clone(s.shadowedRefs)
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
// the test is whether a managed file exists whose contents went unread: every
// file that matched loaded. How many secrets came out of them does not enter
// into it, and neither does matching none, which is EmptySet's. Called per
// request, a reload being able to lose a file at any time.
//
// A [[secret.link]] entry that did not load is not this. It is one ref the
// broker can name, so it refuses that ref and serves the rest rather than
// withholding the output of every command on the host; see DegradedLinks. The
// distinction is what the two hold: a managed file names none of its refs until
// it decrypts, so a file that went unread leaves the broker knowing values are
// missing and not which.
//
// The one link that does reach here is one claiming a ref the managed store
// already defines. That ref is answered, by the store; what is missing is the
// second value the linked file holds for the same name, which no redactor has
// and which is a managed value's kind of missing rather than a link's.
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
		return "a managed value the redactor should hold is missing, so output " +
			"could carry one nothing would cover: " + strings.Join(s.loadErrors, "; ")
	}
	// An empty value set is not this. Nothing configured, a store not written
	// yet, and a store on a volume that is not mounted all leave the broker
	// holding nothing, and holding nothing is not the same as holding less than
	// it should: there is no value for output to carry that the redactor lacks.
	// EmptySet is what says so, and it warns rather than refuses.
	return ""
}

// EmptySet reports why the broker holds no values, or "" when it holds some.
//
// Separate from Unreadable because the two are different states. Unreadable is
// "a managed file exists and went unread", where output could carry a value
// nothing would cover, and it refuses. This one is "there is nothing to cover",
// which is every install on its first day and every host that manages no
// credentials at all, and it serves.
//
// The cost of serving is that a store on a filesystem that is not mounted looks
// exactly like one never written, so a host whose volume is missing runs
// commands with nothing redacted. Nothing inside the broker can tell those two
// apart; what carries the difference is that this is reported at startup, in
// `faramir status` and by `faramir doctor`.
func (s *Store) EmptySet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.values) > 0 {
		return ""
	}
	switch {
	case len(s.config.Patterns) == 0 && len(s.config.Links) == 0:
		return "no [secret] patterns and no [[secret.link]] entries are configured"
	case len(s.unresolvedPatterns) > 0:
		return "no managed file was found: " + strings.Join(s.unresolvedPatterns, "; ")
	case len(s.config.Patterns) == 0:
		// Links alone, every one of them naming a file that is not there.
		return "every [[secret.link]] entry names a file that is not there"
	}
	return "the managed files that loaded held no value"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
