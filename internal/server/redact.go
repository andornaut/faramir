package server

import "github.com/andornaut/faramir/internal/redact"

// redactor takes a redactor over the whole value set. Fresh each call because a
// Redactor carries per-stream state and counts, but the matcher it scans with
// is the store's, compiled once per load: building one here cost every command
// the size of the value set. The sudo grant adds nothing to it: an escalation
// is a decision rather than a value.
func (s *Server) redactor() *redact.Redactor {
	return s.Store.Redactor()
}

// safeDetail is an error message the agent may see, so it goes through the
// redactor: an unexpected error may have interpolated a value into it.
func (s *Server) safeDetail(detail string) string {
	return s.redactor().RedactText(detail)
}

// redactEach covers the command line an audit record carries. The broker never
// substitutes a value into argv, but a caller can, and this record goes to
// disk: what ran stays legible as "mysql -p«SECRET:db/root»".
func redactEach(r *redact.Redactor, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.RedactText(s)
	}
	return out
}
