package agentcfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// WithoutProjectConfig removes routing hooks by the same identity enrolment
// uses when merging them. Permission rules retain the operator's protections:
// a rendered rule may have existed before enrolment wrote the same string.
func WithoutProjectConfig(existing []byte) ([]byte, error) {
	doc, err := decodeSettings(existing)
	if err != nil {
		return nil, err
	}
	changed := false
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for event, value := range hooks {
			list, ok := value.([]any)
			if !ok {
				return nil, fmt.Errorf("hooks.%s: expected a hook list", event)
			}
			kept := mergeList(list, nil, nil)
			if !reflect.DeepEqual(list, kept) {
				hooks[event] = kept
				changed = true
			}
		}
	} else if value, exists := doc["hooks"]; exists && value != nil {
		return nil, errors.New("hooks: expected an object")
	}
	if !changed {
		return existing, nil
	}
	return encodeSettings(doc)
}

// WithoutAntigravityHook removes the account-wide hook the Antigravity family's
// asset writes, which is the whole of the top-level antigravityHookKey entry,
// and leaves every other key alone. A file left with nothing in it stays as
// `{}`: it is the agent's file, not faramir's.
func WithoutAntigravityHook(existing []byte) ([]byte, error) {
	doc, err := decodeSettings(existing)
	if err != nil {
		return nil, err
	}
	if _, present := doc[antigravityHookKey]; !present {
		return existing, nil
	}
	delete(doc, antigravityHookKey)
	return encodeSettings(doc)
}

// decodeSettings is one JSON object, numbers kept as written.
func decodeSettings(existing []byte) (map[string]any, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(existing))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("expected exactly one settings object")
	}
	if doc == nil {
		return nil, errors.New("expected a settings object")
	}
	return doc, nil
}

// encodeSettings spells a settings object as MergeJSON does, so a file this
// cleans and one a merge writes compare equal.
func encodeSettings(doc map[string]any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// WithoutProjectSection removes exactly one marked block, preserving all bytes
// outside it. Ambiguous markers require an operator's repair before removal.
func WithoutProjectSection(existing []byte) ([]byte, error) {
	begin, end := []byte(SectionBegin), []byte(SectionEnd)
	starts, ends := bytes.Count(existing, begin), bytes.Count(existing, end)
	if starts == 0 && ends == 0 {
		if carriesAStaleSection(existing, "# Credentials\n") {
			return nil, errStaleSection
		}
		return existing, nil
	}
	start, stop := bytes.Index(existing, begin), bytes.Index(existing, end)
	if starts != 1 || ends != 1 || stop < start {
		return nil, errHalfMarked
	}
	out := append([]byte{}, existing[:start]...)
	return append(out, existing[stop+len(end):]...), nil
}
