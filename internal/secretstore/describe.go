package secretstore

// What the store says about itself: to an agent, which names nothing, and to
// an operator, which names what failed and why.

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

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

// DegradedCounts is Degraded with the refs counted rather than named, for the
// one surface the agent reads. Same states and same consequences, so a caller
// reading it knows what is wrong and how much of it, and `sudo faramir doctor`
// is where each is named.
//
// Counted rather than named because a ref that is in no redactor is a value
// nothing tokenizes, and handing the agent its name is handing it something
// worth targeting. The counts say a value like that exists, which the exit
// status already said: without them, `status` exits 1 and nothing anywhere says
// why.
func (s *Store) DegradedCounts() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var why []string
	if len(s.degradedLinks) > 0 {
		why = append(why, fmt.Sprintf("%d linked ref(s) did not load", len(s.degradedLinks)))
	}
	if len(s.refused) > 0 {
		why = append(why, fmt.Sprintf("%d ref(s) cannot be redacted, so they are "+
			"never injected", len(s.refused)))
	}
	if len(s.shadowedRefs) > 0 {
		why = append(why, fmt.Sprintf("%d ref(s) are defined with different values "+
			"by more than one managed file, so one value is in no redactor",
			len(s.shadowedRefs)))
	}
	if len(s.loadErrors) > 0 {
		why = append(why, fmt.Sprintf("%d managed file(s) did not load", len(s.loadErrors)))
	}
	if len(why) == 0 {
		return ""
	}
	return strings.Join(why, "; ") +
		". `sudo faramir doctor` names each of them and says what to do about it"
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
// withholding the output of every command on the host; see degradedLinks. The
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
	case s.unconfirmed && (len(s.state) > 0 || len(s.linkState) > 0):
		return ""
	case s.unconfirmed:
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
