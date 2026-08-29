package install

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

// The trees that have been enrolled, and for which agents. Nothing else can
// answer that: a tree carries an agent's settings without naming the account
// they were written for, and a home carries deny rules without naming the trees
// that need them.
//
// Written by `init-project` and read by `doctor`, which otherwise guesses which
// agents are in use from what is in the home. A guess is wrong in both
// directions: a leftover directory reads as in use, and a tree enrolled for an
// agent that leaves no trace in the home reads as absent.
//
// Advisory, and allowed to be stale: a tree can be deleted or moved with
// nothing to tell this file, so a missing directory is an entry to report
// rather than a fault. Nothing here is a boundary.
const enrolledFile = "enrolled.json"

// EnrolledTree is one enrolment: the tree, the account working in it, and the
// agents it was enrolled for.
type EnrolledTree struct {
	Dir       string   `json:"dir"`
	AgentUser string   `json:"agent_user"`
	Agents    []string `json:"agents"`
}

// enrolledPath is where the record lives, beside the config it belongs to.
func enrolledPath(configDir string) string {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	return filepath.Join(configDir, enrolledFile)
}

// readEnrolled is what has been enrolled, or nothing. A file that will not
// parse reads as empty: refusing to examine an install over it would make this
// record matter more than it is.
func readEnrolled(configDir string) []EnrolledTree {
	trees, _ := readEnrolledWhy(configDir)
	return trees
}

// readEnrolledWhy is readEnrolled and why it came back empty, for the two
// places that say so out loud. A record that could not be read is not the same
// as one naming nothing, and reporting the first as the second tells an
// operator with 25 enrolled trees that they have none.
//
// Empty where the file is simply not there: a host that has enrolled nothing
// has no record, and that is the ordinary state rather than a fault.
func readEnrolledWhy(configDir string) ([]EnrolledTree, string) {
	path := enrolledPath(configDir)
	body, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return nil, ""
	case err != nil:
		return nil, err.Error()
	}
	var trees []EnrolledTree
	if err := json.Unmarshal(body, &trees); err != nil {
		return nil, path + ": " + err.Error()
	}
	return trees, ""
}

// recordEnrolment adds or updates this tree's entry. One entry per directory,
// sorted so the file does not churn between runs, and the agents are the ones
// this run enrolled plus the ones an earlier run did that the tree still
// carries. 0600: `init-project` writes it and `doctor` reads it, both as
// root.
//
// An entry naming no agent is still recorded. The enrolment shared the tree and
// wrote its instructions file whether or not an agent was found, and doctor
// checks that file off this record: dropping the entry would leave a tree
// faramir has written to and reports nothing about.
func recordEnrolment(configDir string, tree EnrolledTree) error {
	if tree.Dir == "" {
		return nil
	}
	// The record as it stands, compared again at the write. Two enrolments each
	// read it, add their own tree and write the whole file back, so one entry is
	// lost and the enrolment that lost it reported success: a tree that is
	// enrolled and unrecorded is one `faramir init` stops maintaining and
	// `doctor` stops checking, with nothing said.
	before, err := recordDigest(configDir)
	if err != nil {
		return err
	}
	trees := readEnrolled(configDir)
	// Kept from the earlier entry, but only where the tree still shows the agent:
	// enrolling one by name does not say the others have gone, and dropping them
	// is a tree `doctor` stops checking those agents' account-wide rules for.
	//
	// Bounded by what is there, because an enrolled agent whose rules are missing
	// from the home is a `doctor` failure: a name that could never leave would
	// fail the command for ever on an agent the operator had removed. Every
	// agent this enrols leaves something detect names.
	present := detectAgents(scopeTree, tree.Dir)
	for _, existing := range trees {
		if existing.Dir != tree.Dir {
			continue
		}
		for _, name := range existing.Agents {
			if slices.Contains(tree.Agents, name) || !slices.Contains(present, name) {
				continue
			}
			tree.Agents = append(tree.Agents, name)
		}
	}
	trees = slices.DeleteFunc(trees, func(other EnrolledTree) bool {
		return other.Dir == tree.Dir
	})
	sort.Strings(tree.Agents)
	trees = append(trees, tree)
	sort.Slice(trees, func(i, j int) bool { return trees[i].Dir < trees[j].Dir })

	body, err := json.MarshalIndent(trees, "", "  ")
	if err != nil {
		return err
	}
	// Written beside the file and renamed over it, as every other write here is:
	// doctor reads this, and a run interrupted partway through a truncating write
	// leaves a record that does not parse, which readEnrolled takes for no
	// enrolment at all.
	_, err = fsys{}.writeFileExpecting(enrolledPath(configDir), append(body, '\n'), 0o600, before)
	return err
}

// recordDigest is the record as it stands, or nil where there is none: a first
// enrolment writes the file rather than editing it.
func recordDigest(configDir string) ([]byte, error) {
	body, err := os.ReadFile(enrolledPath(configDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return sum[:], nil
}

// enrolledAgents is every agent named by an enrolment whose tree is still
// there, and the entries whose tree is gone. The second is reported rather
// than cleaned up: an unmounted tree is not a deleted one.
func enrolledAgents(configDir string) (agents []string, stale []EnrolledTree) {
	for _, tree := range readEnrolled(configDir) {
		if !exists(tree.Dir) {
			stale = append(stale, tree)
			continue
		}
		for _, name := range tree.Agents {
			if !slices.Contains(agents, name) {
				agents = append(agents, name)
			}
		}
	}
	sort.Strings(agents)
	return agents, stale
}
