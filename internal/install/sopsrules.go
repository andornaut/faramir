package install

import (
	"fmt"
	"os"
	"slices"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// sopsRules is the part of .sops.yaml anything here reads back: which age
// recipients the creation rules list.  Every other key sops understands is the
// operator's business.
type sopsRules struct {
	CreationRules []struct {
		// Both spellings sops accepts.  This writes key_groups; the
		// comma-separated shorthand is what a hand-edited file often has.
		Age       string `yaml:"age"`
		KeyGroups []struct {
			Age []string `yaml:"age"`
		} `yaml:"key_groups"`
	} `yaml:"creation_rules"`
}

// sopsRecipients is every age recipient .sops.yaml lists, in order, without
// repeats.  Across every rule rather than the one matching the store:
// re-implementing sops' selection would be a second answer free to disagree
// with sops', and the question here is only whether a key is in the file at
// all.
func sopsRecipients(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules sopsRules
	if err := yaml.Unmarshal(body, &rules); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var found []string
	add := func(recipient string) {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" || slices.Contains(found, recipient) {
			return
		}
		found = append(found, recipient)
	}
	for _, rule := range rules.CreationRules {
		for _, recipient := range strings.Split(rule.Age, ",") {
			add(recipient)
		}
		for _, group := range rule.KeyGroups {
			for _, recipient := range group.Age {
				add(recipient)
			}
		}
	}
	return found, nil
}
