package install

// Merging faramir's keys into an agent's config rather than replacing the file.
// These files belong to the project or the operator and hold hooks, MCP servers
// and permission rules faramir knows nothing about; a .dist beside them
// converges on nothing. Only the keys faramir writes are touched, including
// inside an object it also writes to.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// mergeJSON returns ours merged into existing. An unparseable or empty file is
// an error rather than something to overwrite, losing an agent's configuration
// to a stray comma not being a repair this is entitled to make.
//
// wrote is what faramir last rendered into this file; see writtenrules.go. A
// string in that list and not in ours is one an entry no longer backs, and it
// comes out. A string nobody recorded is the operator's and stays, whatever it
// looks like.
func mergeJSON(existing, ours []byte, wrote []string) ([]byte, error) {
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
	merged, err := mergeValue(into, from, wrote)
	if err != nil {
		return nil, err
	}
	// Two-space indent and a trailing newline, matching the assets, so an
	// already-merged file compares equal next run. encoding/json sorts keys.
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// argvKeys name a command line rather than a set. A list under one of these is
// ordered and positional, so faramir's replaces what is there instead of being
// unioned into it: unioning two argv leaves the program an earlier release
// installed standing as the new one's first argument, and what runs is neither
// of them. Only a key both sides declare is merged at all, so this reaches
// faramir's own entries and not an operator's.
var argvKeys = map[string]bool{"command": true, "args": true}

func mergeValue(into, from any, wrote []string) (any, error) {
	fromMap, fromIsMap := from.(map[string]any)
	intoMap, intoIsMap := into.(map[string]any)
	if fromIsMap && intoIsMap {
		out := make(map[string]any, len(intoMap)+len(fromMap))
		maps.Copy(out, intoMap)
		for key, value := range fromMap {
			if current, ok := out[key]; ok && !argvKeys[key] {
				merged, err := mergeValue(current, value, wrote)
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
		return mergeList(intoList, fromList, wrote), nil
	}

	// A scalar, or the shapes disagree. faramir's value wins: a file holding a
	// string where a hook list belongs is one an agent cannot load.
	return from, nil
}

// mergeList merges by element kind. Strings are their own identity and union.
// Objects are hook and server entries: what faramir wrote is taken out and
// re-added, so a relocated or renamed binary is self-correcting rather than a
// hook pointing at a path that no longer exists.
func mergeList(into, from []any, wrote []string) []any {
	out := make([]any, 0, len(into)+len(from))
	for _, element := range into {
		if text, isString := element.(string); isString {
			if containsValue(from, element) {
				continue
			}
			// Written by an earlier run and not rendered by this one, so the
			// entry behind it is gone. An operator's own line is named by no
			// record and stays.
			if slices.Contains(wrote, text) {
				continue
			}
			out = append(out, element)
			continue
		}
		pruned, keep := withoutFaramir(element)
		if !keep {
			continue
		}
		out = append(out, pruned)
	}
	return append(out, from...)
}

// withoutFaramir is an element with faramir's own entries taken out of the
// lists inside it, and whether what is left is worth keeping.
//
// Per entry rather than per element: an agent's hook registration is a matcher
// and a list of what to run under it, and adding your own to the matcher group
// faramir already wrote is the ordinary edit rather than a contrived one.
// Dropping the group over the entry inside it would take yours with it, which
// is the deletion merging exists to avoid.
//
// An element that runs the binary itself is faramir's and goes. So does one
// whose list this emptied: a matcher group holding nothing runs nothing, and
// leaving it would grow the file by a dead entry per run.
func withoutFaramir(element any) (any, bool) {
	if runsBinary(element) {
		return nil, false
	}
	value, isMap := element.(map[string]any)
	if !isMap {
		return element, true
	}
	out := make(map[string]any, len(value))
	emptied := false
	for key, nested := range value {
		list, isList := nested.([]any)
		if !isList {
			out[key] = nested
			continue
		}
		kept := make([]any, 0, len(list))
		for _, entry := range list {
			if pruned, keep := withoutFaramir(entry); keep {
				kept = append(kept, pruned)
			}
		}
		if len(kept) == 0 && len(list) > 0 {
			emptied = true
		}
		out[key] = kept
	}
	return out, !emptied
}

// runsBinary reports whether an element runs the installed binary itself, by
// its own "command". Not what is nested under it: a matcher group carrying
// faramir's hook is not itself faramir's, and that is the whole distinction
// withoutFaramir rests on.
func runsBinary(element any) bool {
	value, isMap := element.(map[string]any)
	if !isMap {
		return false
	}
	return namesBinary(value["command"])
}

func containsValue(list []any, want any) bool {
	return slices.Contains(list, want)
}

// namesBinary reads a "command" value in either shape the agents write: a
// string holding the whole command line, which is what a hook registration is,
// or the argv a server entry takes. Compared on argv[0]'s base name rather than
// on a known path, so an entry from an install whose binary lived elsewhere is
// still recognised, and one whose own path merely holds the word is not. The
// second is ordinary rather than contrived: a checkout under a directory named
// faramir names that path in every hook it registers.
func namesBinary(value any) bool {
	switch command := value.(type) {
	case string:
		program, _, _ := strings.Cut(command, " ")
		return isBinary(program)
	case []any:
		if len(command) == 0 {
			return false
		}
		program, ok := command[0].(string)
		return ok && isBinary(program)
	}
	return false
}

// isBinary reports whether a program is one this project installs, by base name
// so it is recognised wherever it was installed. The "faramir-" prefix with it:
// an earlier layout installed one binary per role, and a hook still pointing at
// one of those fails every command in the project, so it has to be replaced
// rather than left standing beside the new one.
func isBinary(program string) bool {
	name := filepath.Base(program)
	return name == binaryName || strings.HasPrefix(name, binaryName+"-")
}
