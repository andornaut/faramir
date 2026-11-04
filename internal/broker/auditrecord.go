package broker

import (
	"log"

	"github.com/andornaut/faramir/internal/audit"
)

// writeRecord appends one record with no output and logs it under its log_id
// when it is not written. For a record whose loss does not change the answer
// the caller is given, so the journal is where the loss is reported.
func (s *Server) writeRecord(entry map[string]any) {
	if err := s.Audit.Write(entry, audit.Output{}); err != nil {
		log.Printf("%v audit record not written: %v", entry["log_id"], err)
	}
}
