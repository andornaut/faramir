// Package agentcfg is the catalogue of what faramir writes into a coding
// agent's configuration, and what it renders those files from.
//
// One catalogue, read by three callers that must agree. `init` writes the
// account-wide files, `enrol` writes a tree's, and `doctor` re-renders
// both to compare them with what is on disk: a re-render that disagreed with
// the write would report every enrolled host as having drifted.
//
// What it holds:
//
//   - Which agents there are, which files each one keeps in a home and in a
//     tree, and how to tell that an agent is in use.
//   - The paths every agent is refused, rendered into each agent's own spelling
//     from one list, so a rule cannot cover less in one config than in another.
//   - The templates, and the merge that puts faramir's keys into a file the
//     operator owns without touching what else is in it.
//   - The two ledgers a later run reads back: which rules were written into
//     which file, and which trees were enrolled for which agents.
//
// It writes no agent files itself and reports no findings. Enrolling a tree is
// internal/install's; saying whether one has drifted is its doctor's.
package agentcfg
