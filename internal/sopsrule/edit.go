package sopsrule

// Writing the recipient list back, for the commands that manage who can read
// the managed store.
//
// A node tree rather than a re-render: the file carries comments, an escaped
// path_regex and whatever indentation was chosen for it, and marshalling a
// struct back would keep the recipients and throw the rest away.
//
// Every shape this refuses is one where "the recipient list" names more than
// one list: editing either of two is a choice nobody made, and the half not
// edited is what a later reseal seals the store to.

import (
	"bytes"
	"fmt"
	"slices"

	yaml "go.yaml.in/yaml/v3"
)

// SetRecipients returns body with the creation rule's age recipients replaced
// by want, and everything else in the file left as it was.
//
// The same shapes [Load]'s callers refuse are refused here, plus the two only a
// writer cares about: more than one key group, and a group pulling in others by
// merge. Both leave two answers to "which list is the recipient list".
func SetRecipients(body []byte, path string, want []string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	list, err := recipientList(&doc, path)
	if err != nil {
		return nil, err
	}
	list.Kind, list.Tag, list.Style = yaml.SequenceNode, "!!seq", 0
	list.Content = list.Content[:0]
	for _, recipient := range want {
		list.Content = append(list.Content, &yaml.Node{
			Kind: yaml.ScalarNode, Tag: "!!str", Value: recipient,
		})
	}
	return render(&doc, path)
}

// recipientList is the one sequence node an edit may touch, or the reason there
// is not exactly one.
func recipientList(doc *yaml.Node, path string) (*yaml.Node, error) {
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("%s is empty, so it names no creation rule to edit", path)
	}
	rules := mapValue(doc.Content[0], "creation_rules")
	if rules == nil || len(rules.Content) == 0 {
		return nil, fmt.Errorf("%s names no creation rule, so there is no recipient "+
			"list to edit", path)
	}
	if len(rules.Content) > 1 {
		return nil, fmt.Errorf("%s has %d creation rules, and which one governs a file "+
			"depends on its path_regex: edit it by hand and re-key with 'sops "+
			"updatekeys' per file, which is the only thing that can answer it",
			path, len(rules.Content))
	}
	rule := rules.Content[0]
	if mapValue(rule, "shamir_threshold") != nil {
		return nil, fmt.Errorf("%s sets shamir_threshold, so the data key is split "+
			"across key groups: one list of recipients cannot express that, and "+
			"writing one would seal the store to a single group holding every key",
			path)
	}
	groups, shorthand := mapValue(rule, "key_groups"), mapValue(rule, "age")
	if groups == nil {
		if shorthand == nil {
			return nil, fmt.Errorf("%s names no age recipient, so there is no list to "+
				"edit; faramir manages age-encrypted files only", path)
		}
		return shorthand, nil
	}
	// sops reads the shorthand only where there are no key groups, so a file
	// carrying both has a list that governs and a list that does not, and the
	// second is what the next reader of this file may go by.
	if shorthand != nil {
		return nil, fmt.Errorf("%s has both 'age' and 'key_groups' in one rule, and "+
			"sops reads the key groups alone: remove the 'age:' line so there is one "+
			"recipient list, then run this again", path)
	}
	if len(groups.Content) != 1 {
		return nil, fmt.Errorf("%s has %d key groups, and a recipient added to one is "+
			"not added to the others: edit it by hand", path, len(groups.Content))
	}
	group := groups.Content[0]
	if mapValue(group, "merge") != nil {
		return nil, fmt.Errorf("%s pulls recipients in with 'merge', so the list here "+
			"is not the whole of what the rule seals to: edit it by hand", path)
	}
	list := mapValue(group, "age")
	if list == nil {
		return nil, fmt.Errorf("%s has a key group naming no age recipient; faramir "+
			"manages age-encrypted files only", path)
	}
	return list, nil
}

// mapValue is the value beside key in a mapping node, or nil.
func mapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// render writes the tree back at the indentation the installer uses, and refuses
// to hand back something it cannot read again.
//
// Re-read rather than trusted: this file decides who can open every managed
// value, and a write that produced YAML sops would reject leaves a host whose
// next encrypt fails with the store already sealed.
func render(doc *yaml.Node, path string) ([]byte, error) {
	body, err := marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := Parse(body, path); err != nil {
		return nil, fmt.Errorf("%s: the edit would not load again: %w", path, err)
	}
	return body, nil
}

// marshal renders the tree at two-space indentation, which is what the installer
// writes and what a hand-edited file almost always carries.
func marshal(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Recipients rendered on their own is the caller's usual question after an edit:
// what the file will say once it is written.
func recipientsOfBody(body []byte, path string) ([]string, error) {
	rules, err := Parse(body, path)
	if err != nil {
		return nil, err
	}
	return Recipients(rules), nil
}

// Add returns body with recipient appended, and reports whether it was already
// there. Appended rather than sorted: the order is the operator's, and the
// keeper's own key leads it on every host the installer wrote.
func Add(body []byte, path, recipient string) (out []byte, added bool, err error) {
	current, err := recipientsOfBody(body, path)
	if err != nil {
		return nil, false, err
	}
	if slices.Contains(current, recipient) {
		return body, false, nil
	}
	out, err = SetRecipients(body, path, append(slices.Clone(current), recipient))
	return out, err == nil, err
}

// Remove returns body without recipient, and reports whether it was there. The
// last one is refused: a rule naming nobody encrypts to nobody, and sops
// reports that only when the next file is written.
func Remove(body []byte, path, recipient string) (out []byte, removed bool, err error) {
	current, err := recipientsOfBody(body, path)
	if err != nil {
		return nil, false, err
	}
	if !slices.Contains(current, recipient) {
		return body, false, nil
	}
	want := slices.DeleteFunc(slices.Clone(current), func(s string) bool { return s == recipient })
	if len(want) == 0 {
		return nil, false, fmt.Errorf("%s would be left naming no recipient, and a rule "+
			"that seals to nobody fails at the next file sops writes", path)
	}
	out, err = SetRecipients(body, path, want)
	return out, err == nil, err
}
