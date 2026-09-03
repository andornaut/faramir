package secretlink

// INI, which no decoder maps to a tree: read by section and key directly.

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

func iniKeys(data []byte) []string {
	out := []string{}
	section := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		name, _, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if section != "" {
			name = section + "/" + name
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// selectINI reads `key = value` lines, which is the shape of .npmrc and most
// tool dotfiles. A `[section]` header prefixes the keys under it, so the
// selector is "section/key" there and a bare key elsewhere.
//
// Deliberately small: no continuations, no interpolation, and a key given twice
// is refused rather than resolved. Unescaped, unlike the tree kinds, so npm's
// `//registry.npmjs.org/:_authToken` is given as it is written; the cost is
// that a slash in a section or a key can make two entries read alike, which is
// refused below.
func selectINI(data []byte, key string) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("not valid UTF-8")
	}
	// Every entry composing to this selector, by where it came from, and how many
	// entries there were. Two different entries composing alike is this package
	// joining with "/"; the same entry twice is the file's own doing. Both are
	// counted, because neither is this package's to resolve.
	origins := []string{}
	matched := 0
	value, found := "", false
	section := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		name, raw, cut := strings.Cut(line, "=")
		if !cut {
			continue
		}
		name = strings.TrimSpace(name)
		composed := name
		if section != "" {
			composed = section + "/" + name
		}
		if composed != key {
			continue
		}
		matched++
		if origin := iniOrigin(section, name); !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
		if !found {
			value, found = strings.Trim(strings.TrimSpace(raw), `"'`), true
		}
	}
	if len(origins) > 1 {
		return "", fmt.Errorf("matches %d entries (%s): a slash in a section or key "+
			"name makes them read alike, and faramir will not choose which "+
			"credential to inject. Rename one, or link the file with "+
			"type = \"text\"", len(origins), strings.Join(origins, ", "))
	}
	// The same entry more than once. Not resolved here: the readers of these
	// files take the last, so picking the first would inject a credential the
	// tool this file belongs to does not use, and picking the last would still be
	// this package deciding what the file left open. A value that differs between
	// faramir and the tool beside it is worse than one that is absent.
	if matched > 1 {
		return "", fmt.Errorf("sets %s %d times, and faramir will not choose which "+
			"one wins. Remove the duplicates", key, matched)
	}
	if !found {
		return "", fmt.Errorf("has no %s", key)
	}
	if value == "" {
		return "", fmt.Errorf("%s is empty", key)
	}
	return value, nil
}

// iniOrigin names where one matching entry sits, for the refusal above. Names
// only, like everything else this package reports.
func iniOrigin(section, name string) string {
	if section == "" {
		return name + " outside any section"
	}
	return name + " under [" + section + "]"
}
