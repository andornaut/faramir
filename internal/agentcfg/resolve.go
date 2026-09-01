package agentcfg

// Which agents an enrolment configures: the names an operator gave, and what
// `auto` finds on the host.

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"

	"github.com/andornaut/faramir/internal/hostfs"
)

// Which agents an enrolment configures: the names an operator gave, and what
// `auto` finds on the host.

// Auto is the --agent value that means "whichever ones are here", and the
// default on both commands. A name alongside it is configured whether or not
// it is here, so `--agent auto --agent pi` reads as "what is installed, plus
// pi".
const Auto = "auto"

// Scope is where auto looks for evidence: `init` writes into the agent
// account's home, and `init-project` into one tree.
type Scope int

const (
	// ScopeHome is the agent account's home directory.
	ScopeHome Scope = iota
	// ScopeTree is one working tree.
	ScopeTree
)

func (t *Target) markers(scope Scope) []string {
	if scope == ScopeHome {
		return t.DetectHome
	}
	return t.Detect
}

// Known lists the agents this can enrol, sorted for a stable error, and so for
// the flag that takes one to name them rather than carry a copy.
func Known() []string {
	out := make([]string, 0, len(Targets))
	for name := range Targets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Resolve turns --agent values into targets, resolving "auto" against
// what dir carries. An unknown name is an error rather than a skip, which
// would leave an operator believing something is covered.
//
// Naming an agent configures it whether or not it is here and auto only adds
// what it finds, so the result is the union of the two. Returned in a fixed
// order, so a report reads the same twice.
// home is the agent account's home, consulted for an agent that keeps nothing
// of its own beside a project; empty where the caller has none to give, which
// leaves such an agent undetected rather than guessed at.
func Resolve(names []string, scope Scope, dir, home string) ([]*Target, error) {
	if len(names) == 0 {
		names = []string{Auto}
	}
	wanted := map[string]bool{}
	for _, name := range names {
		if name == Auto {
			for _, found := range detectForEnrolment(scope, dir, home) {
				wanted[found] = true
			}
			continue
		}
		if _, ok := Targets[name]; !ok {
			return nil, fmt.Errorf("unknown --agent %q; known agents are %v, or %q",
				name, Known(), Auto)
		}
		wanted[name] = true
	}
	var out []*Target
	for _, name := range Known() {
		if wanted[name] {
			out = append(out, Targets[name])
		}
	}
	return out, nil
}

// detect reports which known agents dir carries evidence of: an agent's
// own configuration in a home, or its per-project configuration in a tree.
// Evidence, not proof -- a directory left behind by trying an agent once reads
// the same as one in daily use -- which is why this only ever adds.
func detect(scope Scope, dir string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	for _, name := range Known() {
		for _, path := range Targets[name].markers(scope) {
			if hostfs.Exists(filepath.Join(dir, path)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// detectForEnrolment is the question auto puts: which agents should this run
// configure here. It is Detect plus the home fallback, which is a
// different question from what a tree carries. [enrolled] asks that other one
// and keeps Detect, an agent's enrolment record being what a tree still
// shows rather than what the host has installed.
func detectForEnrolment(scope Scope, dir, home string) []string {
	out := detect(scope, dir)
	if scope != ScopeTree || home == "" {
		return out
	}
	for _, name := range Known() {
		target := Targets[name]
		if !target.DetectsFromHome || slices.Contains(out, name) {
			continue
		}
		for _, path := range target.DetectHome {
			if hostfs.Exists(filepath.Join(home, path)) {
				out = append(out, name)
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

// Detected is what auto would find in a tree, for the report that names
// what was found and not enrolled.
func Detected(dir, home string) []string {
	return detectForEnrolment(ScopeTree, dir, home)
}
