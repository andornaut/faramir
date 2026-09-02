package secretlink

// Reading one value out of a decoded tree by its selector.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// selectPath walks a decoded tree by a "path/to/key" selector, the same
// spelling the keeper flattens a sops file into, so a ref and a selector read
// the same way. A list is indexed by number. One divergence: the keeper
// escapes nothing, so a sops key that itself carries a "/" flattens to a ref
// that also spells the nested form, where a selector here escapes it. The ref
// grammar has no escape, so renaming such a key is the fix, not spelling it.
func selectPath(tree any, key string) (string, error) {
	node := tree
	walked := ""
	for _, segment := range splitSelector(key) {
		if walked == "" {
			walked = escapeSegment(segment)
		} else {
			walked += "/" + escapeSegment(segment)
		}
		switch container := node.(type) {
		case map[string]any:
			child, ok := container[segment]
			if !ok {
				return "", fmt.Errorf("has no %s", walked)
			}
			node = child
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(container) {
				return "", fmt.Errorf("has no %s: that is a list of %d",
					walked, len(container))
			}
			node = container[index]
		default:
			return "", fmt.Errorf("has no %s: %s is not a table or a list",
				walked, parentOf(walked))
		}
	}
	return scalar(node, key)
}

// splitSelector cuts a selector into segments on unescaped "/", and unescapes
// the rest. A key that holds a slash makes this necessary: a container
// registry file names its entries by URL, so an unescaped
// `auths/https://…/auth` walks four levels that are not there.
//
// The whole-file kinds and ini do not come through here: ini matches a key
// whole, so a slash in one is already literal.
func splitSelector(key string) []string {
	segments := []string{}
	var current strings.Builder
	escaped := false
	for _, r := range key {
		switch {
		case escaped:
			// Only "/" and the escape itself are special; an escape before anything
			// else is a literal backslash.
			if r != '/' && r != '\\' {
				current.WriteRune('\\')
			}
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '/':
			segments = append(segments, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		current.WriteRune('\\')
	}
	return append(segments, current.String())
}

// escapeSegment spells one key so splitSelector reads it back whole. Every
// listing goes through it: a name offered and then refused as a selector is
// worse than none.
func escapeSegment(segment string) string {
	segment = strings.ReplaceAll(segment, `\`, `\\`)
	return strings.ReplaceAll(segment, "/", `\/`)
}

// parentOf names the part of a selector that ran out, for the error above.
func parentOf(walked string) string {
	// Through the selector spelling rather than the last "/" byte: walked is
	// already escaped, so a key holding a slash would otherwise be cut inside
	// itself.
	segments := splitSelector(walked)
	if len(segments) < 2 {
		return "the file"
	}
	parts := make([]string, 0, len(segments)-1)
	for _, segment := range segments[:len(segments)-1] {
		parts = append(parts, escapeSegment(segment))
	}
	return strings.Join(parts, "/")
}

// scalar converts a selected leaf, refusing what is never a credential: the
// same rule the keeper applies when it flattens, a bool putting "true" in the
// value set and redacting half the output.
func scalar(node any, key string) (string, error) {
	switch value := node.(type) {
	case string:
		if value == "" {
			return "", fmt.Errorf("%s is empty", key)
		}
		return value, nil
	case int:
		return strconv.Itoa(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), nil
	case json.Number:
		return value.String(), nil
	case bool:
		return "", fmt.Errorf("%s is a boolean, which is never a secret", key)
	case nil:
		return "", fmt.Errorf("%s is null", key)
	}
	return "", fmt.Errorf("%s is a table or a list, not a value", key)
}
