package secretstore

import (
	"maps"

	"github.com/andornaut/faramir/internal/redact"
)

// Snapshot holds one immutable generation of values, refusals and store health.
// It remains valid across reloads without holding the store's lock.
type Snapshot struct {
	values        map[string]string
	refused       map[string]string
	degradedLinks map[string]string
	compiled      *redact.Values
	unreadable    string
}

// Snapshot captures values, their compiled matcher and serving health together.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	compiled := s.compiled
	if compiled == nil {
		compiled = redact.NewValues(nil, s.Policy)
	}
	return Snapshot{
		values:        maps.Clone(s.values),
		refused:       maps.Clone(s.refused),
		degradedLinks: maps.Clone(s.degradedLinks),
		compiled:      compiled,
		unreadable:    s.unreadableLocked(),
	}
}

// Value returns one secret using the captured generation's refusal reasons.
func (s Snapshot) Value(ref string) (string, error) {
	return value(s.values, s.refused, s.degradedLinks, ref)
}

// Redactor returns an independent redactor over the captured value set.
func (s Snapshot) Redactor() *redact.Redactor {
	return s.compiled.Redactor()
}

// Unreadable reports why the captured generation cannot promise redaction.
func (s Snapshot) Unreadable() string {
	return s.unreadable
}
