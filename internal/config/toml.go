package config

import (
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// rejectUnknownKeys fails on a mistyped key, naming it and the alternatives.
func rejectUnknownKeys(raw map[string]any, known []string, where string) error {
	return rejectUnknown(raw, known, where, "key")
}

// rejectUnknownSections is the same check one level up, over [tables].
func rejectUnknownSections(raw map[string]any, known []string, where string) error {
	return rejectUnknown(raw, known, where, "section")
}

func rejectUnknown(raw map[string]any, known []string, where, noun string) error {
	var unknown []string
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[k] = true
	}
	for k := range raw {
		if !set[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	sorted := append([]string(nil), known...)
	sort.Strings(sorted)
	return fmt.Errorf("%s: unknown %s(s): %s; known %ss: %s",
		where, noun, strings.Join(unknown, ", "), noun, strings.Join(sorted, ", "))
}

// table returns one [section] as a map, rejecting a scalar written in its
// place.
func table(raw map[string]any, key, where string) (map[string]any, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return map[string]any{}, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a [%s] table, got %T", where, key, value)
	}
	out := make(map[string]any, len(m))
	maps.Copy(out, m)
	return out, nil
}

// section reads one named table and refuses its unknown keys, returning the
// "path: [name]" prefix every refusal in it carries. Each loader is this
// preamble and then its own fields.
func section(raw map[string]any, name, path string) (map[string]any, string, error) {
	where := path + ": [" + name + "]"
	sec, err := table(raw, name, path)
	if err != nil {
		return nil, "", err
	}
	if err := rejectUnknownKeys(sec, sectionKeys[name], where); err != nil {
		return nil, "", err
	}
	return sec, where, nil
}

// strField pairs a key with the field it fills; the field's current value is
// its default.
type strField struct {
	key  string
	into *string
}

// strFields fills string fields in the order given, stopping at the first
// refusal so the key named is the same one the loop it replaces would name.
func strFields(sec map[string]any, where string, fields []strField) error {
	for _, f := range fields {
		var err error
		if *f.into, err = str(sec[f.key], where, *f.into); err != nil {
			return err
		}
	}
	return nil
}

func stringList(value any, where string, fallback []string) ([]string, error) {
	if value == nil {
		return fallback, nil
	}
	if s, ok := value.(string); ok {
		return nil, fmt.Errorf("%s: expected a list of strings, got string (write it as [%q])", where, s)
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a list of strings, got %T", where, value)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: expected a string, got %T: %v", where, v, v)
		}
		out = append(out, s)
	}
	return out, nil
}

func stringMap(value any, where string, fallback map[string]string) (map[string]string, error) {
	if value == nil {
		return fallback, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a table of strings, got %T", where, value)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: %s: expected a string, got %T", where, k, v)
		}
		out[k] = s
	}
	return out, nil
}

// boolean is str for a flag key. A value of another type is refused rather than
// read as false: an entry saying `strict = "yes"` means to tighten a rule,
// and taking it as absent would leave the operator a host they think is closed.
func boolean(value any, where, key string, fallback bool) (bool, error) {
	if value == nil {
		return fallback, nil
	}
	on, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("%s: %s expects true or false, got %T", where, key, value)
	}
	return on, nil
}

func str(value any, where string, fallback string) (string, error) {
	if value == nil {
		return fallback, nil
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected a string, got %T", where, value)
	}
	return s, nil
}

func integer(value any, where string, fallback int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	n, ok := value.(int64)
	if !ok {
		return 0, fmt.Errorf("%s: expected an integer, got %T", where, value)
	}
	return int(n), nil
}

// intInRange is the value check the sizes and counts need: concurrency = -1
// panics on startup, 0 refuses every request as busy, and timeout_sec = 0 kills
// every command as it starts.
func intInRange(sec map[string]any, key, where string, fallback, low, high int) (int, error) {
	n, err := integer(sec[key], where, fallback)
	if err != nil {
		return 0, err
	}
	if n < low || n > high {
		if high == maxInt {
			return 0, fmt.Errorf("%s: %s must be at least %d, got %d", where, key, low, n)
		}
		return 0, fmt.Errorf("%s: %s must be between %d and %d, got %d", where, key, low, high, n)
	}
	return n, nil
}

// atLeast is intInRange with no upper bound worth naming.
func atLeast(sec map[string]any, key, where string, fallback, low int) (int, error) {
	return intInRange(sec, key, where, fallback, low, maxInt)
}

const maxInt = int(^uint(0) >> 1)

func readTOML(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config not found: %s", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return raw, nil
}
