package hostfs

// Editing a file faramir does not own: the path is resolved once, and
// everything after goes through that descriptor.

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrNotOperators is a file faramir edits rather than owns whose owner is not
// the account it is being edited for, or a link that lands on one. The message
// carries what to do and names no command, surfacing both through
// sectionProblem and wrapped with its path for an agent's settings.
var ErrNotOperators = errors.New("faramir edits this file but does not own it, " +
	"and it is not the operator's, so nothing was written: root will not write a " +
	"file the owner did not ask it to, and changing the owner would take the file " +
	"from them. A symlink here is followed, so this also covers a link to a file the " +
	"operator does not own, to nothing, or to a file outside the tree being enrolled. " +
	"Give the file to the operator, or point the link at a file they own")

// Edited is where a file faramir edits rather than owns is to be written.
//
// A link that was followed leaves root open on the target's directory and name
// set to the file inside it, and everything after goes through that descriptor,
// so the resolution happens once: a path checked and then written by path is
// resolved twice, and in between the account the agent runs as can replace a
// directory it owns with a link.
//
// The temp-and-rename is kept, so a write that fails partway leaves the file it
// found rather than half of a new one.
type Edited struct {
	// path is where to write, and is what is used when root is nil.
	path string
	// root is the target's directory and name the file inside it, both set only
	// where a link was followed.
	root *os.Root
	name string
	// info is the file as it is, or nil where there is nothing there yet.
	info os.FileInfo
}

func (e *Edited) Close() {
	if e != nil && e.root != nil {
		_ = e.root.Close()
	}
}

// Read is what the file holds now, or nil where there is nothing there.
func (e *Edited) Read() ([]byte, error) {
	var (
		body []byte
		err  error
	)
	if e.root != nil {
		body, err = e.root.ReadFile(e.name)
	} else {
		body, err = os.ReadFile(e.path)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return body, err
}

// EditedFile is where to write a file faramir edits rather than owns: the
// agent's settings, the credentials section. The caller closes it.
//
// These commands run as root on paths inside directories the account the agent
// runs as can write, which is what each check here is for:
//
//   - A link is followed, so a dotfiles manager's file is updated in place
//     rather than replaced by a regular file. Only to a regular file the
//     operator owns; within bounds where it may land, naming the enrolled tree
//     where there is one and empty in a home.
//   - An existing file must be the operator's. Root would otherwise edit
//     somebody else's file, and chowning it away from them is worse.
//   - Nothing there is no error: the caller creates it, and creation is where
//     ownership is faramir's to set.
//
// uid == keep asks nothing, for a caller with no operator in hand.
//
// A nil info means there is nothing there. Otherwise the caller takes the
// mode and ownership from it rather than passing keep: a write renames a new
// file over the path, so the replacement would otherwise be root's.
func (f FS) EditedFile(path string, uid int, within string) (*Edited, error) {
	link, err := os.Lstat(path)
	exists := true
	switch {
	case errors.Is(err, os.ErrNotExist):
		exists = false
	// A dry run is the one form that does not need root, so a path it cannot look
	// at is left to the write, which writes nothing either way.
	case f.DryRun && errors.Is(err, os.ErrPermission):
		return &Edited{path: path}, nil
	case err != nil:
		return nil, err
	}
	target := path
	if exists && link.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		switch {
		case f.DryRun && errors.Is(err, os.ErrPermission):
			return &Edited{path: path}, nil
		// A dangling link names a path that is not there, and creating it would put
		// a root-made file wherever the link aims.
		case errors.Is(err, os.ErrNotExist):
			return nil, ErrNotOperators
		case err != nil:
			return nil, err
		}
		target = resolved
	}
	// The directory, resolved, and the bound applied to it rather than to the
	// file: Lstat declines to follow only the last component, so a symlinked
	// directory carries the write wherever it points. Creation goes through here
	// too.
	dir, err := filepath.EvalSymlinks(filepath.Dir(target))
	switch {
	// Nothing there yet: the write creates the file and its caller the directory,
	// both inside the tree. It is also what a precondition sees, asking this of
	// a home before anything has been written to it.
	case errors.Is(err, os.ErrNotExist):
		return &Edited{path: path}, nil
	case f.DryRun && errors.Is(err, os.ErrPermission):
		return &Edited{path: path}, nil
	case err != nil:
		return nil, err
	}
	if within != "" && !Encloses(within, dir) {
		return nil, ErrNotOperators
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		if f.DryRun {
			return &Edited{path: path}, nil
		}
		return nil, err
	}
	name := filepath.Base(target)
	out := &Edited{path: filepath.Join(dir, name), root: root, name: name}
	if !exists {
		// Nothing to check and nothing to keep: the caller creates it, and creation
		// is where ownership is faramir's to set.
		return out, nil
	}
	info, err := out.Stat()
	switch {
	// A path that cannot be read is a different problem from one somebody else
	// owns, and saying the wrong one sends an operator after the wrong fix.
	case f.DryRun && errors.Is(err, os.ErrPermission):
		out.Close()
		return &Edited{path: path}, nil
	case errors.Is(err, os.ErrNotExist):
		out.Close()
		return nil, ErrNotOperators
	case err != nil:
		out.Close()
		return nil, err
	case !info.Mode().IsRegular():
		out.Close()
		return nil, ErrNotOperators
	}
	switch wrong, err := WrongOwner(info, uid, Keep); {
	case err != nil, wrong:
		out.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrNotOperators
	}
	out.info = info
	return out, nil
}

// Path is the file the write lands on: the link's target where one was
// followed, and what was asked for where none was. Two paths answering with one
// of these are two writes with one survivor, which is what a caller asking for
// several at once has to see.
func (e *Edited) Path() string { return e.path }

// Info is the file as it was when EditedFile opened it, or nil where there was
// nothing there. Not Stat: what a caller keeps of an existing file -- its mode
// and its owner -- has to be what was there when the descriptor was opened,
// not what the path answers for later.
func (e *Edited) Info() os.FileInfo { return e.info }

// Stat asks the descriptor where there is one, so what is checked is what is
// written rather than whatever the path names by then.
func (e *Edited) Stat() (os.FileInfo, error) {
	if e.root != nil {
		return e.root.Stat(e.name)
	}
	return os.Stat(e.path)
}

// WriteEdited writes data where editedFile said, through the descriptor where
// one was opened.
func (f FS) WriteEdited(e *Edited, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	if e.root == nil {
		return f.WriteFile(e.path, data, mode, uid, gid)
	}
	return f.writeInto(e.root, e.name, data, mode, uid, gid, Unread())
}
