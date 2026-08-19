// Package sopsrule reads the creation rules out of a .sops.yaml: which rules
// there are, and which age recipients each one seals to.
//
// One reader for every caller that asks: `faramir recipient reseal` re-encrypts
// the store to what the rules say and `faramir doctor` reports whether the
// keeper is still among them, so two readers could disagree about whether a
// store is healthy.
//
// Parsed rather than matched with a regex: a rule is a list entry whose keys
// may be in any order, may be written in flow style, and need not lead with
// path_regex. What is kept out of the shipped binary is the sops libraries,
// and a YAML parser is not one of them.
package sopsrule

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// Rule is one creation rule, reduced to what any caller here asks about.
type Rule struct {
	// Recipients is who this rule seals to, in the order the file lists them and
	// without repeats.
	Recipients []string
	// ShamirThreshold is how many key groups have to come together to open a file,
	// and zero where the rule does not split the data key. Carried so a caller
	// can refuse a rule it would otherwise flatten.
	ShamirThreshold int
}

// Load is every creation rule in the file at path.
func Load(path string) ([]Rule, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(body, path)
}

// Parse is Load for a caller holding the bytes.
func Parse(body []byte, path string) ([]Rule, error) {
	var parsed file
	if err := yaml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	rules := make([]Rule, 0, len(parsed.CreationRules))
	for _, raw := range parsed.CreationRules {
		rules = append(rules, Rule{
			Recipients:      raw.recipients(),
			ShamirThreshold: raw.ShamirThreshold,
		})
	}
	return rules, nil
}

// Recipients is every recipient across every rule, without repeats, for the
// caller whose question is only whether a key is named in the file at all.
func Recipients(rules []Rule) []string {
	var out []string
	for _, rule := range rules {
		for _, recipient := range rule.Recipients {
			if !slices.Contains(out, recipient) {
				out = append(out, recipient)
			}
		}
	}
	return out
}

type file struct {
	CreationRules []rule `yaml:"creation_rules"`
}

type rule struct {
	// Both spellings sops takes. `age` is the shorthand a hand-edited file often
	// carries, and only there does sops accept a comma-separated string; the
	// installer writes key_groups.
	Age             ageList    `yaml:"age"`
	KeyGroups       []keyGroup `yaml:"key_groups"`
	ShamirThreshold int        `yaml:"shamir_threshold"`
}

// keyGroup is one group of a rule's key groups. Merge is followed because sops
// follows it: a reader that stopped at the top level would report a rule as
// sealing to fewer recipients than it does, and a caller re-encrypting from
// that answer drops every reader named only under a merge.
//
// Age is a plain list rather than the shorthand: sops takes a comma-separated
// string only in a rule's own `age`.
type keyGroup struct {
	Age   []string   `yaml:"age"`
	Merge []keyGroup `yaml:"merge"`
}

// recipients is every age key this group seals with, its merged groups included.
func (g keyGroup) recipients() []string {
	out := slices.Clone(g.Age)
	for _, merged := range g.Merge {
		out = append(out, merged.recipients()...)
	}
	return out
}

// recipients is who the rule actually seals to. The key groups alone where a
// rule carries both, because that is what sops does: it reads the `age`
// shorthand only when there are no key groups, so a rule with `age: A` beside a
// group naming B seals to B and to nobody else.
func (r rule) recipients() []string {
	var out []string
	add := func(recipients []string) {
		for _, recipient := range recipients {
			if recipient != "" && !slices.Contains(out, recipient) {
				out = append(out, recipient)
			}
		}
	}
	if len(r.KeyGroups) > 0 {
		for _, group := range r.KeyGroups {
			add(group.recipients())
		}
		return out
	}
	add(r.Age)
	return out
}

// ageList is one `age:` value however it was written: a single recipient, a
// comma-separated string of them, or a list.
type ageList []string

func (a *ageList) UnmarshalYAML(node *yaml.Node) error {
	var list []string
	if err := node.Decode(&list); err == nil {
		*a = list
		return nil
	}
	var one string
	if err := node.Decode(&one); err != nil {
		return err
	}
	for field := range strings.SplitSeq(one, ",") {
		if field = strings.TrimSpace(field); field != "" {
			*a = append(*a, field)
		}
	}
	return nil
}

// coverTimeout bounds one Covers probe. Long enough for sops to encrypt a line
// of YAML on a loaded host, short enough that a plugin recipient
// (age1yubikey1...) sitting waiting for somebody to touch a key costs a few
// seconds rather than a command that never returns.
const coverTimeout = 10 * time.Second

// Covers reports whether the creation rules at configPath govern target.
//
// Asked of sops rather than answered here: which rule governs a file is sops'
// question, and a second implementation of the match is free to disagree.
//
// A throwaway document under the target's own name, encrypted with
// --filename-override so the rule is matched against where the file really
// lives; nothing is written near the store and the ciphertext is discarded.
// recipients are named on the command line where the caller has them, so a rule
// whose own recipients are unusable still answers the question.
func Covers(sopsPath, configPath string, recipients []string, target string) (bool, error) {
	dir, err := os.MkdirTemp("", "faramir-rule-check-")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	probe := filepath.Join(dir, filepath.Base(target))
	if err := os.WriteFile(probe, probeBody(target), 0o600); err != nil {
		return false, err
	}
	// --config rather than the SOPS_CONFIG variable: a sops old enough not to know
	// the variable searches from the working directory instead, which would
	// answer about a different file.
	argv := []string{"--config", configPath, "--encrypt", "--filename-override", target}
	if len(recipients) > 0 {
		argv = append(argv, "--age", strings.Join(recipients, ","))
	}
	ctx, cancel := context.WithTimeout(context.Background(), coverTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sopsPath, append(argv, probe)...)
	// Fixed: the rule is named in the argv above, and nothing else about this
	// process's environment should reach sops.
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home,
		"LANG=C.UTF-8",
	}
	if _, err := cmd.Output(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && strings.Contains(string(exit.Stderr), "no matching creation rules") {
			return false, nil
		}
		// Anything else is a rule this could not put the question to; the caller
		// reports it as unchecked rather than as an uncovered file.
		return false, fmt.Errorf("%w: %s", err, lastLine(err))
	}
	return true, nil
}

// probeBody is a document sops can parse as the store the target's name
// selects. The name decides the store, so a YAML body under a .json or .env
// name is one sops rejects before it says anything about creation rules. The
// set is what sops supports rather than what an install writes; anything
// unrecognised is YAML, which is what sops falls back to.
func probeBody(target string) []byte {
	const key = "faramir_rule_check"
	switch strings.ToLower(filepath.Ext(target)) {
	case ".json":
		return []byte(`{"` + key + `": "probe"}` + "\n")
	case ".env":
		return []byte(key + "=probe\n")
	case ".ini":
		return []byte("[faramir]\n" + key + " = probe\n")
	}
	return []byte(key + ": probe\n")
}

// lastLine is the last line of what a failed sops printed, or "".
func lastLine(err error) string {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || len(exit.Stderr) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(exit.Stderr)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
