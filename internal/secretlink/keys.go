package secretlink

// The selectors a linked file offers, for an operator choosing one.

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/BurntSushi/toml"
	yaml "go.yaml.in/yaml/v3"
)

// maxKeyChars bounds one offered selector, a file being able to hold a line as
// long as it likes and the offers being a list rather than a value.
const maxKeyChars = 120

// keysIn is Keys against a file, read through the same bound Read uses.
func keysIn(path, kind string) ([]string, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	return Keys(kind, data), nil
}

// Keys is every selector this file offers, for the message an operator gets
// when theirs named nothing. Names only, never values. Sorted, and empty for
// the whole-file kinds.
func Keys(kind string, data []byte) []string {
	var tree any
	switch kind {
	case kindJSON:
		if json.Unmarshal(data, &tree) != nil {
			return nil
		}
	case KindYAML:
		if yaml.Unmarshal(data, &tree) != nil {
			return nil
		}
	case kindTOML:
		var table map[string]any
		if toml.Unmarshal(data, &table) != nil {
			return nil
		}
		tree = table
	case kindINI:
		return iniKeys(data)
	default:
		return nil
	}
	out := []string{}
	collect(tree, "", &out)
	sort.Strings(out)
	return out
}

// collect walks to the leaves, which are the only things a selector can name.
func collect(node any, prefix string, out *[]string) {
	join := func(segment string) string {
		if prefix == "" {
			return escapeSegment(segment)
		}
		return prefix + "/" + escapeSegment(segment)
	}
	switch container := node.(type) {
	case map[string]any:
		for key, child := range container {
			collect(child, join(key), out)
		}
	case []any:
		for i, child := range container {
			collect(child, join(strconv.Itoa(i)), out)
		}
	default:
		if prefix != "" {
			*out = append(*out, prefix)
		}
	}
}
