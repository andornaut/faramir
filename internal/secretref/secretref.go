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

// scheme is what a ref carries when it is written as a URI. `faramir refs`
// prints that form and a [[secret.link]] entry stores the name inside it, so
// the two spellings meet wherever an operator pastes one into the other.
const scheme = "faramir://"

var (
	uriRe = regexp.MustCompile(`^` + scheme + `(` + refPattern + `)$`)
	refRe = regexp.MustCompile(`^` + refPattern + `$`)
)

// Bare is the name inside a faramir:// URI, or the argument unchanged where it
// carries no scheme. For a command that takes a ref as an operand: what refs
// prints is the URI, what the config stores is the name, and refusing the
// spelling the operator has in front of them buys nothing.
func Bare(ref string) string {
	return strings.TrimPrefix(strings.TrimSpace(ref), scheme)
}

// Valid reports whether a bare ref, with no scheme, is one Parse would return.
func Valid(ref string) bool { return refRe.MatchString(ref) }

// Parse returns the ref inside a faramir:// URI.
func Parse(uri string) (string, error) {
	m := uriRe.FindStringSubmatch(strings.TrimSpace(uri))
	if m == nil {
		return "", fmt.Errorf("invalid secret reference %q; expected faramir://path/to/key", uri)
	}
	return m[1], nil
}

// envNameRe is what a variable may be called. Not the same shape as a ref: a
// variable may open with an underscore and a ref may not, and a ref may carry
// "/" and "." where a variable may not.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvName reports whether name can be an environment variable. Held here
// beside the ref grammar because a NAME=faramir://ref pair is checked against
// both, and the CLI refuses one where it can still name the file and line.
func ValidEnvName(name string) bool { return envNameRe.MatchString(name) }
