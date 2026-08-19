package sopsrule

// Reading recipients off a managed file rather than out of a rule: who it is
// actually sealed to, as opposed to who the rule says it should be.
//
// Here beside the rule reader because the two answers are only useful together.
// A caller that has one and not the other cannot tell a store that agrees with
// its rule from one that has drifted, and a second implementation of either is
// free to disagree with the first.

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

// ErrNoRecipients is a file that read fine and names no age recipient: not
// encrypted at all, or encrypted to something other than age. Distinguished
// from a read failure because only one of the two means the caller learned
// nothing, and a caller reporting on a store has to tell them apart.
var ErrNoRecipients = errors.New("no age recipient")

// ageRecipient matches the cleartext recipient field sops writes into a file it
// encrypted, in every store it writes: `recipient: age1...` in YAML and JSON,
// and sops_age__list_0__map_recipient=age1... in the dotenv and ini forms. The
// metadata is cleartext, so this needs no key.
//
// A regex rather than a YAML library, which would undo keeping the sops
// libraries out of the shipped binary for one cleartext field.
var ageRecipient = regexp.MustCompile(`recipient"?\s*[:=]\s*"?(age1[0-9a-z]+)`)

// SealedTo is the age recipients a managed file is already encrypted to.
func SealedTo(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, match := range ageRecipient.FindAllSubmatch(body, -1) {
		recipient := string(match[1])
		if !seen[recipient] {
			seen[recipient] = true
			out = append(out, recipient)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no age recipient, so there is nothing to "+
			"re-encrypt it to; faramir manages age-encrypted files only: %w",
			path, ErrNoRecipients)
	}
	return out, nil
}

// Same reports whether two recipient sets name the same keys, regardless of the
// order they are written in, so a rule that merely lists them differently is not
// a store that has drifted.
func Same(was, wanted []string) bool {
	if len(was) != len(wanted) {
		return false
	}
	seen := make(map[string]int, len(was))
	for _, r := range was {
		seen[r]++
	}
	for _, r := range wanted {
		seen[r]--
		if seen[r] < 0 {
			return false
		}
	}
	return true
}
