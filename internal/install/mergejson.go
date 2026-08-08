package install

// Merging faramir's keys into an agent's config rather than replacing the file.
//
// These files belong to the project or to the operator and hold hooks, MCP
// servers and permission rules faramir knows nothing about.  Writing the whole
// file would lose them, and writing a .dist beside it converges on nothing: it
// is rewritten every run, the merge is done by hand or not at all, and the copy
// stays as a second version that disagrees with the live one.
//
// Only the keys faramir puts in are touched.  Everything else in the file is
// carried through, including keys inside an object faramir also writes to.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// mergeJSON returns ours merged into existing.  An unparseable or empty
// existing file is an error rather than something to overwrite: it is the
// operator's, and losing an agent's whole configuration to a stray comma is not
// a repair this is entitled to make.
func mergeJSON(existing, ours []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return ours, nil
	}
	var into, from any
	if err := json.Unmarshal(existing, &into); err != nil {
		return nil, fmt.Errorf("parsing the file already there: %w", err)
	}
	if err := json.Unmarshal(ours, &from); err != nil {
		return nil, fmt.Errorf("parsing what would be written: %w", err)
	}
	merged, err := mergeValue(into, from)
	if err != nil {
		return nil, err
	}
	// Two-space indent and a trailing newline, matching the assets, so a file
	// this has already merged compares equal on the next run and reports no
	// change.  Key order is whatever encoding/json emits, which is sorted and
	// therefore stable.
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func mergeValue(into, from any) (any, error) {
	fromMap, fromIsMap := from.(map[string]any)
	intoMap, intoIsMap := into.(map[string]any)
	if fromIsMap && intoIsMap {
		out := make(map[string]any, len(intoMap)+len(fromMap))
		for key, value := range intoMap {
			out[key] = value
		}
		for key, value := range fromMap {
			if current, ok := out[key]; ok {
				merged, err := mergeValue(current, value)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				out[key] = merged
				continue
			}
			out[key] = value
		}
		return out, nil
	}

	fromList, fromIsList := from.([]any)
	intoList, intoIsList := into.([]any)
	if fromIsList && intoIsList {
		return mergeList(intoList, fromList)
	}

	// A scalar, or the two disagree about the shape.  faramir's value wins:
	// where it writes a key at all it writes the value that key has to have,
	// and a file holding a string where a hook list belongs is one an agent
	// cannot load anyway.
	return from, nil
}

// mergeList merges by element kind, because the two kinds in these files carry
// identity differently.
//
// Strings are their own identity, so they union: a deny rule the operator added
// is kept, and one of faramir's that is already there is not added twice.
//
// Objects are hook and server entries, whose identity is what they invoke.  An
// existing one that names faramir is dropped and re-added from what faramir
// writes now, so a run that changes the command it registers replaces the entry
// rather than leaving a second one beside it.  That is what makes a renamed or
// relocated binary self-correcting instead of a hook pointing at a path that no
// longer exists, which fails every command the agent runs.
func mergeList(into, from []any) ([]any, error) {
	out := make([]any, 0, len(into)+len(from))
	for _, element := range into {
		if _, isString := element.(string); isString {
			if containsValue(from, element) {
				continue
			}
			out = append(out, element)
			continue
		}
		mentions, err := mentionsFaramir(element)
		if err != nil {
			return nil, err
		}
		if mentions {
			continue
		}
		out = append(out, element)
	}
	return append(out, from...), nil
}

func containsValue(list []any, want any) bool {
	for _, element := range list {
		if element == want {
			return true
		}
	}
	return false
}

// mentionsFaramir reports whether an element names this project anywhere inside
// it, at any depth: the command a hook runs, the key an MCP server is under, or
// an argument to either.  Matched on the serialised element rather than on a
// known path, so an entry left by an install whose binary lived somewhere else
// is still recognised as the one being replaced.
func mentionsFaramir(element any) (bool, error) {
	encoded, err := json.Marshal(element)
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(string(encoded)), "faramir"), nil
}
