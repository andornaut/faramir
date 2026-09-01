package agentcfg

// Writing an agent's files, and refusing the paths a run cannot write. The
// catalogue those files come from is in targets.go.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andornaut/faramir/internal/hostfs"
)

// WriteFiles writes one list of an agent's files under root, and reports
// whether it changed anything and what it wrote. One function for both
// commands: `init` writes the account-wide rules into a home and `init-project`
// Claude Code's routing hook into a tree.
//
// render is the caller's, the two rendering against different things: the
// install layout for an account file, the target's own data for a tree's.
//
// inTree says which root this is. A tree's files are group-owned so the client
// group can read what the hook is written into, and a link out of the tree
// would carry that group to a file the enrolment was never pointed at. A home's decide neither, so an existing file keeps its group and
// a link may land wherever the operator keeps their dotfiles.
// configDir is where the record of what faramir last wrote lives, so a merge
// can take out a rule the config no longer declares. Empty leaves the record
// unread and unwritten, which is a merge that only ever adds.
// warn receives what could not be recorded, which is not a reason to stop:
// the rules reached the file, and what was lost is the note saying faramir
// wrote them. Said rather than swallowed, because the run that meets it next
// removes nothing and nothing else would explain why.
func WriteFiles(fs hostfs.FS, warn func(string, ...any), root, configDir string,
	uid, gid int, dirMode os.FileMode, inTree bool,
	render func(File) ([]byte, error), files []File) (bool, []string, error) {
	changed := false
	var written []string
	for _, file := range files {
		path := filepath.Join(root, file.Path)
		// Only created, never re-owned: the directory is the account's or the
		// project's, and with the operator's own group, `init` running as root so a
		// new ~/.config would otherwise be operator:root.
		//
		// Skipped where the file sits at the root, which has an owner already. In
		// a tree, every level: see ensureDirs. In a home the leaf only, an
		// ancestor there being ~/.config, which 0755 is right for.
		if parent := filepath.Dir(path); parent != filepath.Clean(root) {
			ensure := func() error {
				_, err := fs.EnsureDir(parent, dirMode, uid, gid, false)
				return err
			}
			if inTree {
				// The sticky bit on the directory this file lands in, applied as it is
				// created rather than left to the share's walk: that walk runs before
				// this writes anything, so a directory created here would sit
				// group-writable with no sticky bit until a second enrolment settled
				// it, and in that window the account brokered commands run as can
				// unlink the rules file and put its own there. Only the last
				// component: sharetree.stickyDirs names the directory a kept file sits
				// in and no level above it, and a level this made sticky that the walk
				// does not would be cleared on the next run.
				ensure = func() error {
					return fs.EnsureDirsIn(root, parent, dirMode, dirMode|os.ModeSticky,
						uid, gid)
				}
			}
			if err := ensure(); err != nil {
				return changed, written, err
			}
		}
		// A link followed and the owner checked: these are the operator's and the
		// project's files, and both commands run as root on a path the account the
		// agent runs as can write. See hostfs.FS.EditedFile.
		bound := ""
		if inTree {
			bound = root
		}
		// The rules this run renders into the file, for the record kept after the
		// write. Nil where nothing was merged, which is a file faramir owns
		// outright rather than one it writes into.
		var rendered []string
		spot, err := fs.EditedFile(path, uid, bound)
		if err != nil {
			return changed, written, fmt.Errorf("%s: %w", path, err)
		}
		data, err := render(file)
		if err != nil {
			spot.Close()
			return changed, written, err
		}
		// Merged, not overwritten: the file is the operator's or the project's to
		// edit, and only the keys faramir writes are touched. Through the merge
		// even with nothing to merge into, so the first write is byte-for-byte
		// what the second would produce.
		if file.Merge {
			was, err := spot.Read()
			if err != nil {
				spot.Close()
				return changed, written, err
			}
			// What an earlier run rendered into this file, so a rule the config
			// no longer declares comes out rather than accumulating beside the
			// new ones. See writtenrules.go.
			merged, err := MergeJSON(was, data, ReadWrittenRules(configDir)[path])
			if err != nil {
				spot.Close()
				return changed, written, fmt.Errorf("%s: %w", path, err)
			}
			rendered = jsonStrings(data)
			data = merged
		}
		// Ownership is set on a file this creates and left alone on one already
		// there, editedFile having established that it is the operator's. The
		// group is asserted in a tree, where the client group has to read these;
		// in a home it decides nothing. The mode is asserted throughout: these
		// carry the hook, and group-writable is what they must never be.
		writeUID, writeGID := uid, gid
		if spot.Info() != nil {
			// Read off the file: a write renames a new file over the path, so
			// anything not named here comes out owned by root.
			ownerUID, ownerGID := hostfs.OwnerOf(spot.Info())
			writeUID = ownerUID
			if !inTree {
				writeGID = ownerGID
			}
		}
		made, err := fs.WriteEdited(spot, data, file.Mode, writeUID, writeGID)
		spot.Close()
		if err != nil {
			return changed, written, err
		}
		// After the write and not before it: a record naming rules that never
		// reached the file would have the next run trying to remove what is not
		// there. Not fatal, because the rules did reach the file and what was
		// lost is the note saying faramir wrote them; said, because the run that
		// meets it next removes nothing and nothing else would explain why.
		if rendered != nil {
			if err := recordWrittenRules(configDir, path, rendered); err != nil && warn != nil {
				warn("what faramir wrote into %s was not recorded (%v), so a later "+
					"run will not offer to take those rules out again. Re-run this "+
					"command once nothing else is writing the install", path, err)
			}
		}
		changed = changed || made
		written = append(written, path)
	}
	return changed, written, nil
}

// RefuseUnwritable asks, of every file a run is about to edit, the question the
// write will ask, and answers with what it would refuse.
//
// Asked before anything is written: an enrolment's first step chowns and chmods
// every file in the tree and nothing undoes that, so finding out afterwards
// that a settings file is not the operator's is too late.
//
// Every path, not the first refusal: an operator fixing these wants the list.
// One call per root, and every path a run writes there in it: two of them
// resolving to one file is a refusal, which a caller asking in several calls
// would not find.
func RefuseUnwritable(fs hostfs.FS, root string, uid int, within string, paths []string) []string {
	var refused []string
	// The file each path resolves to, against the path that named it first. A
	// link is followed, so two of these can be one file: see oneFileTwice.
	claimed := map[string]string{}
	for _, rel := range paths {
		path := filepath.Join(root, rel)
		spot, err := fs.EditedFile(path, uid, within)
		target := ""
		if spot != nil {
			target = spot.Path()
		}
		spot.Close()
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		// The same path twice is one file written once, which is what two agents
		// reading one file of their own is. Only two different paths landing on
		// one are two writes with one survivor.
		switch first, taken := claimed[target]; {
		case !taken:
			claimed[target] = path
		case first != path:
			refused = append(refused, fmt.Sprintf("%s: %s", path, oneFileTwice(first)))
		}
	}
	return refused
}

// oneFileTwice is what a run says about two of its paths resolving to one file.
// Blocked rather than reconciled: each file is written for the agent that reads
// it, so one standing in for two keeps whichever was written last and leaves an
// agent holding another agent's configuration. It names the path that claimed
// the file first, neither half of the pair being wrong on its own.
func oneFileTwice(first string) string {
	return "this and " + first + " are one file, and each is written for the agent that reads it, so nothing was " +
		"written: only the last write would survive. A link between them is what makes " +
		"this, so point one at a file of its own"
}

// EditedPaths are the files one agent's enrolment edits at this scope, relative
// to the root, which is what RefuseUnwritable is asked about.
func EditedPaths(target *Target, inTree bool, instructions string) []string {
	var out []string
	files := target.AccountFiles
	if inTree {
		files = target.Files
	}
	for _, file := range files {
		out = append(out, file.Path)
	}
	if instructions != "" {
		out = append(out, instructions)
	}
	return out
}

// HomeEditedPaths are the files `init` edits in a home for these agents, each
// named once: two agents can read one instructions file.
func HomeEditedPaths(targets []*Target) []string {
	var out []string
	seen := map[string]bool{}
	for _, target := range targets {
		for _, path := range EditedPaths(target, false, target.HomeInstructions) {
			if seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}
