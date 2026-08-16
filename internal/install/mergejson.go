package install

// Merging faramir's keys into an agent's config rather than replacing the file.
// These files belong to the project or the operator and hold hooks, MCP servers
// and permission rules faramir knows nothing about; a .dist beside them
// converges on nothing.  Only the keys faramir writes are touched, including
// inside an object it also writes to.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// mergeJSON returns ours merged into existing.  An unparseable or empty file is
// an error rather than something to overwrite, losing an agent's configuration
// to a stray comma not being a repair this is entitled to make.
func mergeJSON(existing, ours []byte) ([]byte, error) {
	// An absent file still goes through the merge, so what is written the first
	// time is what a merge would produce the second: returning the asset as it
	// was authored leaves the next run re-serialising it with keys sorted, which
	// is one real diff on a tree nobody changed.
	if len(bytes.TrimSpace(existing)) == 0 {
		existing = []byte("{}")
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
	// Two-space indent and a trailing newline, matching the assets, so an
	// already-merged file compares equal next run.  encoding/json sorts keys.
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
		maps.Copy(out, intoMap)
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

	// A scalar, or the shapes disagree.  faramir's value wins: a file holding a
	// string where a hook list belongs is one an agent cannot load.
	return from, nil
}

// mergeList merges by element kind.  Strings are their own identity and union.
// Objects are hook and server entries, identified by what they invoke: an
// existing one naming faramir is dropped and re-added, so a relocated binary is
// self-correcting rather than a hook pointing at a path that no longer
// exists.
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
	return slices.Contains(list, want)
}

// mentionsFaramir reports whether an element names this project at any depth.
// Matched on the serialised element rather than a known path, so an entry from
// an install whose binary lived elsewhere is still recognised.
func mentionsFaramir(element any) (bool, error) {
	encoded, err := json.Marshal(element)
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(string(encoded)), "faramir"), nil
}
