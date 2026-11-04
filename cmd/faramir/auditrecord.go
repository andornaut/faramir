package main

import (
	"fmt"
	"os"

	"github.com/andornaut/faramir/internal/audit"
)

// writeAudit appends one record with no output and warns on stderr when it is
// not written. The exit status stays the command's own: the operation has
// already succeeded or failed, and a lost record changes neither.
func writeAudit(label string, sink *audit.Log, record map[string]any) {
	if err := sink.Write(record, audit.Output{}); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: audit record not written: %v\n", label, err)
	}
}
