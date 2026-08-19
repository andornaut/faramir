// Package secretlink reads one secret out of a file the operator's own tools
// maintain, rather than out of the managed sops store.  A linked value is not
// copied anywhere: the file stays where its tool expects it, so rotating a
// credential is that tool's business and nothing here goes stale.
//
// What a link is for is redaction as much as injection.  A value the agent can
// already read is plaintext one command away; linking it puts it in the value
// set, so a brokered command that prints it gets a token back, and the deny
// rules take away the direct read.  Linking something the agent *cannot* reach
// is the opposite trade and is not what this is for: every managed value is
// reachable through env_refs by any brokered command.
//
// No error here carries file content.  A decoder's own message often quotes the
// line it failed on, and these messages reach the daemon log and `--check`, so
// the parse errors are replaced rather than wrapped.
package secretlink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	yaml "go.yaml.in/yaml/v3"
)

// The kinds, which are how a file is read rather than what it is called.
const (
	// KindText is the whole file, surrounding whitespace trimmed.  A keyfile or a
	// single-line token.
	KindText = "text"
	// KindBase64 is the whole file encoded, for one that is not text.  The value
	// injected is the encoding, so whatever consumes it decodes.
	KindBase64 = "base64"
	// KindJSON, KindYAML, KindTOML and KindINI select one value out of a
	// structured file.
	KindJSON = "json"
	KindYAML = "yaml"
	KindTOML = "toml"
	KindINI  = "ini"
)

// MaxBytes bounds a linked file.  A credential file is small, and a link
// pointed at something else should fail rather than be read into the value set.
const MaxBytes = 1 << 20

// Kinds is every kind, for the config parser's error message and its tests.
// Ordered as declared rather than alphabetically: the whole-file kinds first,
// then the ones that select.
func Kinds() []string {
	return []string{KindText, KindBase64, KindJSON, KindYAML, KindTOML, KindINI}
}

// NeedsKey reports whether a kind selects part of a file, and so requires a
// `key`.  The whole-file kinds refuse one, a key there naming nothing.
func NeedsKey(kind string) bool {
	switch kind {
	case KindJSON, KindYAML, KindTOML, KindINI:
		return true
	}
	return false
}

// Read returns the value a link selects.  The error says what is wrong with the
// file or the selector and never what is in it.
func Read(path, kind, key string) (string, error) {
	data, err := readBounded(path)
	if err != nil {
		return "", err
	}
	return Extract(kind, key, data)
}

// readBounded reads at most MaxBytes plus one byte, so a file over the cap is
// reported rather than truncated into the value set.
func readBounded(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("larger than %d bytes, so it is not the credential "+
			"file this link meant to name", MaxBytes)
	}
	return data, nil
}

// Extract pulls the value out of a file's bytes.
func Extract(kind, key string, data []byte) (string, error) {
	switch kind {
	case KindText:
		if !utf8.Valid(data) {
			return "", errors.New("not valid UTF-8, so it cannot be matched in output " +
				"or held in an environment variable; use type = \"base64\"")
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", errors.New("holds no value")
		}
		return value, nil
	case KindBase64:
		if len(data) == 0 {
			return "", errors.New("holds no value")
		}
		return base64.StdEncoding.EncodeToString(data), nil
	case KindJSON:
		var tree any
		if err := json.Unmarshal(data, &tree); err != nil {
			return "", errors.New("is not valid JSON")
		}
		return selectPath(tree, key)
	case KindYAML:
		var tree any
		if err := yaml.Unmarshal(data, &tree); err != nil {
			return "", errors.New("is not valid YAML")
		}
		return selectPath(tree, key)
	case KindTOML:
		var table map[string]any
		if err := toml.Unmarshal(data, &table); err != nil {
			return "", errors.New("is not valid TOML")
		}
		return selectPath(table, key)
	case KindINI:
		return selectINI(data, key)
	}
	return "", fmt.Errorf("unknown type %q; known types: %s",
		kind, strings.Join(Kinds(), ", "))
}

// KeysIn is Keys against a file, read through the same bound Read uses: a link
// pointed at something too large to be a credential must not be read whole to
// enumerate it either.
func KeysIn(path, kind string) ([]string, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	return Keys(kind, data), nil
}

// Keys is every selector this file offers, for the message an operator gets
// when theirs named nothing.  Names only: a key is not a value, and printing
// the values would defeat the whole arrangement.
//
// Sorted, and empty for the whole-file kinds, which select nothing.
func Keys(kind string, data []byte) []string {
	var tree any
	switch kind {
	case KindJSON:
		if json.Unmarshal(data, &tree) != nil {
			return nil
		}
	case KindYAML:
		if yaml.Unmarshal(data, &tree) != nil {
			return nil
		}
	case KindTOML:
		var table map[string]any
		if toml.Unmarshal(data, &table) != nil {
			return nil
		}
		tree = table
	case KindINI:
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

// selectPath walks a decoded tree by a "path/to/key" selector, the same
// spelling the keeper flattens a sops file into, so a ref and a selector read
// the same way.  A list is indexed by number.
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
// the rest.  A key that holds a slash is what makes this necessary: a container
// registry file names its entries by URL, so an unescaped `auths/https://…/auth`
// walks four levels that are not there.  Escaped, it names the two that are.
//
// The whole-file kinds and ini do not come through here.  ini matches a key
// whole, so a slash in one is already literal, and escaping it would break the
// npm registry keys that are the reason ini is a kind at all.
func splitSelector(key string) []string {
	segments := []string{}
	var current strings.Builder
	escaped := false
	for _, r := range key {
		switch {
		case escaped:
			// Only "/" and the escape itself are special.  An escape before anything
			// else is a literal backslash, so a Windows path is not rejected for one.
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

// escapeSegment spells one key so splitSelector reads it back whole.  Every
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
	// itself and the error would name a parent nobody wrote.
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

// scalar converts a selected leaf, refusing what is never a credential.  The
// same rule the keeper applies when it flattens: a bool would put "true" in the
// value set and redact half the output.
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

// selectINI reads `key = value` lines, which is the shape of .npmrc, .netrc's
// relatives and most tool dotfiles.  A `[section]` header prefixes the keys
// under it, so the selector is "section/key" there and a bare key elsewhere.
//
// Deliberately small: no continuations, no interpolation, no duplicate-key
// policy beyond first wins.  A file needing more than this is one the operator
// should select out of with a different type.
//
// Unescaped, unlike the tree kinds: a selector here is one key matched whole,
// which is what lets npm's `//registry.npmjs.org/:_authToken` be given as it is
// written.  The cost is that a slash in a section or a key can make two
// different entries read alike, and that case is refused below rather than
// guessed at.
func selectINI(data []byte, key string) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("not valid UTF-8")
	}
	// Every entry composing to this selector, by where it came from.  A file
	// holding one key twice is the file's own ambiguity and INI's answer is first
	// wins; two *different* entries composing alike is this package joining with
	// "/", and choosing between them would be choosing which credential to
	// inject.
	origins := []string{}
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
		if origin := iniOrigin(section, name); !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
		if !found {
			value, found = strings.Trim(strings.TrimSpace(raw), `"'`), true
		}
	}
	if len(origins) > 1 {
		return "", fmt.Errorf("names %d entries at once (%s), and choosing between "+
			"them would be choosing which credential to inject: a slash in a section "+
			"or a key makes them read alike. Rename one, or link the file with "+
			"type = \"text\"", len(origins), strings.Join(origins, ", "))
	}
	if !found {
		return "", fmt.Errorf("has no %s", key)
	}
	if value == "" {
		return "", fmt.Errorf("%s is empty", key)
	}
	return value, nil
}

// iniOrigin names where one matching entry sits, for the refusal above.  Names
// only, like everything else this package reports.
func iniOrigin(section, name string) string {
	if section == "" {
		return name + " outside any section"
	}
	return name + " under [" + section + "]"
}
