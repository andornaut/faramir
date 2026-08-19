// Package secretref parses the faramir:// reference syntax, separately from the
// store so the protocol layer can validate one without depending on anything
// that holds a value.
package secretref

import (
	"fmt"
	"regexp"
	"strings"
)

// refPattern is the ref itself, without the scheme. Written once because two
// things hold to it: the URI a caller sends, and the `ref` a [[secret.link]]
// entry declares. A link whose ref no caller could spell would load and then be
// unreachable.
const refPattern = `[A-Za-z0-9][A-Za-z0-9._/-]*`

var (
	URIRe = regexp.MustCompile(`^faramir://(` + refPattern + `)$`)
	refRe = regexp.MustCompile(`^` + refPattern + `$`)
)

// Valid reports whether a bare ref, with no scheme, is one Parse would return.
func Valid(ref string) bool { return refRe.MatchString(ref) }

// Parse returns the ref inside a faramir:// URI.
func Parse(uri string) (string, error) {
	m := URIRe.FindStringSubmatch(strings.TrimSpace(uri))
	if m == nil {
		return "", fmt.Errorf("invalid secret reference %q; expected faramir://path/to/key", uri)
	}
	return m[1], nil
}
