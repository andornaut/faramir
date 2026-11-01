package agentcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// WithoutProjectConfig removes routing hooks by the same identity enrolment
// uses when merging them. Permission rules retain the operator's protections:
// a rendered rule may have existed before enrolment wrote the same string.
func WithoutProjectConfig(existing []byte) ([]byte, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(existing))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one settings object")
	}
	if doc == nil {
		return nil, fmt.Errorf("expected a settings object")
	}
	changed := false
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for event, value := range hooks {
			list, ok := value.([]any)
			if !ok {
				return nil, fmt.Errorf("hooks.%s: expected a hook list", event)
			}
			kept := mergeList(list, nil, nil)
			before, _ := json.Marshal(list)
			after, _ := json.Marshal(kept)
			if !bytes.Equal(before, after) {
				hooks[event] = kept
				changed = true
			}
		}
	} else if value, exists := doc["hooks"]; exists && value != nil {
		return nil, fmt.Errorf("hooks: expected an object")
	}
	if !changed {
		return existing, nil
	}
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
