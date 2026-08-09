// Package secretref parses the secret:// reference syntax, separately from the
// store so the protocol layer can validate one without depending on anything
// that holds a value.
package secretref

import (
	"fmt"
	"regexp"
	"strings"
)

var URIRe = regexp.MustCompile(`^secret://([A-Za-z0-9][A-Za-z0-9._/-]*)$`)

// Parse returns the ref inside a secret:// URI.
func Parse(uri string) (string, error) {
	m := URIRe.FindStringSubmatch(strings.TrimSpace(uri))
	if m == nil {
		return "", fmt.Errorf("invalid secret reference %q; expected secret://path/to/key", uri)
	}
	return m[1], nil
}
