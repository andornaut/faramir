package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

// The trees that have been enrolled, and for which agents.
//
// Nothing else can answer that question.  An enrolment writes into the tree and
// into the operator's home, and neither half says where the other went: a tree
// carries an agent's settings without naming the account they were written for,
// and a home carries deny rules without naming the trees that need them.  So
// `doctor`, which examines the install rather than the operator's directories,
// could see that an agent had rules and not that a project was relying on them.
//
// Written by `init-project` because that is the command that knows, and read by
// `doctor`, which otherwise guesses which agents are in use from what happens to
// be in the home.  A guess is wrong in both directions: a leftover directory
// reads as in use, and a tree enrolled for an agent that leaves no trace in the
// home reads as absent.
//
// Advisory, and allowed to be stale.  A tree can be deleted or moved with
// nothing to tell this file, so a reader treats a missing directory as an entry
// to report rather than as a fault, and nothing here is a boundary: what an
// agent may reach is decided by file modes and by the rules themselves.
const enrolledFile = "enrolled.json"

// EnrolledTree is one enrolment: the tree, the account working in it, and the
// agents it was enrolled for.
type EnrolledTree struct {
	Dir      string   `json:"dir"`
	Operator string   `json:"operator"`
	Agents   []string `json:"agents"`
}

// enrolledPath is where the record lives, beside the config it belongs to.
func enrolledPath(configDir string) string {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	return filepath.Join(configDir, enrolledFile)
}

// readEnrolled is what has been enrolled, or nothing.  A file that will not
// parse reads as empty: it is a record of convenience, and refusing to examine
// an install because of it would make it matter more than it is.
func readEnrolled(configDir string) []EnrolledTree {
	body, err := os.ReadFile(enrolledPath(configDir))
	if err != nil {
		return nil
	}
	var trees []EnrolledTree
	if err := json.Unmarshal(body, &trees); err != nil {
		return nil
	}
	return trees
}

// recordEnrolment adds or replaces this tree's entry.  Keyed by directory, so
// re-enrolling a tree for different agents says the later thing rather than
// both, and sorted so the file does not churn between runs.
//
// 0600: `init-project` writes it and `doctor` reads it, both as root, so
// nothing else has cause to open it.  What it holds is the paths of an
// operator's own projects, which is not a secret but is nobody else's business
// either.
func recordEnrolment(configDir string, tree EnrolledTree) error {
	if len(tree.Agents) == 0 || tree.Dir == "" {
		return nil
	}
	trees := readEnrolled(configDir)
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
	return os.WriteFile(enrolledPath(configDir), append(body, '\n'), 0o600)
}

// enrolledAgents is every agent named by an enrolment whose tree is still
// there, and the entries whose tree is gone.  The second is reported rather
// than cleaned up: this file is not the authority on what exists, and removing
// an entry for a tree that is merely unmounted would lose the record of it.
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
