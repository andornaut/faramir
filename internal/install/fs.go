package install

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// keep is the uid or gid value that leaves ownership as it is.
const keep = -1

// fsys is the filesystem side of an install. Every method reports whether it
// changed anything, so a configuration manager need not stat the host before
// and after. With dryRun set each computes the same answer and writes
// nothing.
type fsys struct{ dryRun bool }

// ensureDir creates a directory if it is absent and asserts its mode and
// ownership if it is not. own=false leaves an existing one alone, for the
// directories the operator may have set up themselves.
func (f fsys) ensureDir(path string, mode os.FileMode, uid, gid int, own bool) (bool, error) {
	info, err := os.Stat(path)
	switch {
	// A dry run runs unprivileged and cannot answer for a directory it cannot
	// look inside. Reported as no change, so the rest is still produced.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.dryRun {
			return true, nil
		}
		// Every directory MkdirAll creates, not just the leaf: an intermediate left
		// root-owned at 0700 is one its owner cannot traverse. The ancestors take
		// the ownership but not the mode: the secrets directory's 2770 applied to
		// its parent would hand write and rename on it to every brokered
		// command.
		created := missingAncestors(path)
		if err := os.MkdirAll(path, mode); err != nil {
			return false, err
		}
		for _, dir := range created {
			// MkdirAll applies the umask and ignores setgid.
			ancestorMode := os.FileMode(0o755)
			if dir == path {
				ancestorMode = mode
			}
			if err := os.Chmod(dir, ancestorMode); err != nil {
				return false, err
			}
			if err := chown(dir, uid, gid); err != nil {
				return false, err
			}
		}
		return true, nil
	case err != nil:
		return false, err
	case !info.IsDir():
		return false, fmt.Errorf("%s exists and is not a directory", path)
	}
	if !own {
		return false, nil
	}
	// The same rule as ensureOwnership: the mode and owner set below are what take
	// this directory back from the account the agent runs as, and through a link
	// they would land on its target. os.Stat above followed it; this does not.
	link, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if link.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a symlink, and the mode and owner asserted "+
			"here would land on whatever it points at: replace it with a real directory",
			path)
	}
	changed := info.Mode().Perm() != mode.Perm() || info.Mode()&os.ModeSetgid != mode&os.ModeSetgid
	if wrong, err := wrongOwner(info, uid, gid); err != nil {
		return false, err
	} else if wrong {
		changed = true
	}
	if !changed || f.dryRun {
		return changed, nil
	}
	return true, chmodAndChown(path, mode, uid, gid)
}

// refuseUncreatableDirs is refuseUnenterableDirs for a home, where the writer
// asks a different question: writeAgentFiles calls ensureDir on the leaf parent
// with own=false, which reads through a symlink deliberately, an agent's
// settings directory being wherever the operator keeps their dotfiles. Asking
// the stricter question here would refuse an install that then writes fine.
func refuseUncreatableDirs(root string, mode os.FileMode, uid, gid int, paths []string) []string {
	var refused []string
	ask := fsys{dryRun: true}
	for _, rel := range paths {
		dir := filepath.Dir(filepath.Join(root, rel))
		if dir == filepath.Clean(root) {
			continue
		}
		if _, err := ask.ensureDir(dir, mode, uid, gid, false); err != nil {
			refused = append(refused, err.Error())
		}
	}
	return refused
}

// refuseUnenterableDirs asks, of every directory these files sit in, the
// question creating it will ask: see fsys.ensureDirsIn. A component that is a
// symlink is a directory a write would make outside root, which refuseUnwritable
// cannot answer for while the parent does not exist.
//
// Asked through a dry run, which answers and writes nothing, so both callers
// get it before what they do next cannot be undone: init-project before the
// share that walks the tree, and init before it hands files to the accounts.
// paths are relative to root, as the writers take them.
func refuseUnenterableDirs(root string, mode os.FileMode, uid, gid int, paths []string) []string {
	var refused []string
	ask := fsys{dryRun: true}
	for _, rel := range paths {
		dir := filepath.Dir(filepath.Join(root, rel))
		if err := ask.ensureDirsIn(root, dir, mode, mode, uid, gid); err != nil {
			refused = append(refused, err.Error())
		}
	}
	return refused
}

// ensureDirsIn creates every missing directory between root and path, each with
// mode and owner, and leaves the ones already there alone. The last component
// gets leafMode instead: it is the one that ends up holding a file, and in a
// tree that means the sticky bit, which the intermediate levels do not carry.
//
// Pinned to root rather than walked by path, unlike ensureDir: this runs as
// root in a tree the account the agent runs as can write, so a symlinked
// component would put a new directory outside the tree and hand it to the
// client group. An os.Root refuses to traverse a symlink at all, and the case
// below is what says which component is a link.
//
// A dry run answers the same question and writes nothing, which is what lets
// preflight ask it before the share that cannot be undone.
func (f fsys) ensureDirsIn(root, path string, mode, leafMode os.FileMode, uid, gid int) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside %s", path, root)
	}
	if rel == "." {
		return nil
	}
	handle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()

	at := ""
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		at = filepath.Join(at, part)
		here := filepath.Join(root, at)
		want := mode
		if i == len(parts)-1 {
			want = leafMode
		}
		// Lstat, so a symlink is seen as itself rather than as what it points at.
		info, err := handle.Lstat(at)
		switch {
		case err == nil && info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink, and a directory created inside it "+
				"would land wherever it points rather than in %s: replace it with a "+
				"real directory", here, root)
		case err == nil && info.IsDir():
			// The project's own, and not this command's to re-own: the share settles
			// the mode of a directory that was already there.
			continue
		case err == nil:
			return fmt.Errorf("%s exists and is not a directory", here)
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
		if f.dryRun {
			// Nothing below it can be there either, so there is nothing left to
			// ask.
			return nil
		}
		if err := handle.Mkdir(at, want.Perm()); err != nil {
			return err
		}
		// Mkdir applies the umask and ignores setgid and sticky, as MkdirAll does.
		if err := handle.Chmod(at, want); err != nil {
			return err
		}
		if uid != keep || gid != keep {
			if err := handle.Lchown(at, uid, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureOwnership fixes an existing file's owner, group and mode without
// touching its contents. Lstat to decide and a descriptor to repair, never a
// path-based chmod: the directories this walks are writable by the account the
// assertion exists to constrain, so a symlink planted there would take root's
// chmod to its target.
func (f fsys) ensureOwnership(path string, mode os.FileMode, uid, gid int) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Blocked rather than skipped: the mode and owner asserted here are what
		// keep the file out of the agent's reach.
		return false, fmt.Errorf("%s is a symlink, and its mode and owner would be "+
			"applied to whatever it points at: replace it with a regular file", path)
	}
	wrong, err := wrongOwner(info, uid, gid)
	if err != nil {
		return false, err
	}
	if info.Mode().Perm() == mode.Perm() && !wrong {
		return false, nil
	}
	if f.dryRun {
		return true, nil
	}
	return true, chmodAndChown(path, mode, uid, gid)
}

// ensurePrivateFile creates an empty 0600 file if it is absent and asserts its
// mode and ownership either way, for a file whose owner would otherwise be
// whichever uid writes to it first. 0600 rather than a parameter: the one
// thing this creates is the audit log.
func (f fsys) ensurePrivateFile(path string, uid, gid int) (bool, error) {
	const mode = os.FileMode(0o600)
	switch _, err := os.Lstat(path); {
	// A dry run runs unprivileged and cannot look inside a directory the broker
	// owns. Reported as no change, as ensureDir does.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.dryRun {
			return true, nil
		}
		handle, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return false, err
		}
		_ = handle.Close()
		// The open applied the umask to mode; this does not.
		return true, chmodAndChown(path, mode, uid, gid)
	case err != nil:
		return false, err
	}
	return f.ensureOwnership(path, mode, uid, gid)
}

// chmodAndChown repairs one file through a descriptor opened O_NOFOLLOW, so the
// file checked and the file changed are the same file even if the path is
// re-pointed in between. O_NONBLOCK so a fifo does not wait for a writer.
func chmodAndChown(path string, mode os.FileMode, uid, gid int) error {
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Chmod(mode); err != nil {
		return err
	}
	if uid == keep && gid == keep {
		return nil
	}
	return handle.Chown(uid, gid)
}

// errNotOperators is a file faramir edits rather than owns whose owner is not
// the account it is being edited for, or a link that lands on one. The message
// carries what to do and names no command, surfacing both through
// sectionProblem and wrapped with its path for an agent's settings.
var errNotOperators = errors.New("this is a file faramir edits rather than owns, " +
	"and it is not the operator's, so nothing was written: editing it would be root " +
	"writing a file it was never asked to, and chowning it to make that true would " +
	"take it from whoever has it. A symlink here is followed, so this also names one " +
	"landing on a file the operator does not own, on nothing, or outside the tree " +
	"being enrolled. Give it to the operator, or point the link at their own file")

// edited is where a file faramir edits rather than owns is to be written.
//
// A link that was followed leaves root open on the target's directory and name
// set to the file inside it, and everything after goes through that descriptor,
// so the resolution happens once: a path checked and then written by path is
// resolved twice, and in between the account the agent runs as can replace a
// directory it owns with a link.
//
// The temp-and-rename is kept, so a write that fails partway leaves the file it
// found rather than half of a new one.
type edited struct {
	// path is where to write, and is what is used when root is nil.
	path string
	// root is the target's directory and name the file inside it, both set only
	// where a link was followed.
	root *os.Root
	name string
	// info is the file as it is, or nil where there is nothing there yet.
	info os.FileInfo
}

func (e *edited) close() {
	if e != nil && e.root != nil {
		_ = e.root.Close()
	}
}

// read is what the file holds now, or nil where there is nothing there.
func (e *edited) read() ([]byte, error) {
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

// editedFile is where to write a file faramir edits rather than owns: the
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
func (f fsys) editedFile(path string, uid int, within string) (*edited, error) {
	link, err := os.Lstat(path)
	exists := true
	switch {
	case errors.Is(err, os.ErrNotExist):
		exists = false
	// A dry run is the one form that does not need root, so a path it cannot look
	// at is left to the write, which writes nothing either way.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return &edited{path: path}, nil
	case err != nil:
		return nil, err
	}
	target := path
	if exists && link.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		switch {
		case f.dryRun && errors.Is(err, os.ErrPermission):
			return &edited{path: path}, nil
		// A dangling link names a path that is not there, and creating it would put
		// a root-made file wherever the link aims.
		case errors.Is(err, os.ErrNotExist):
			return nil, errNotOperators
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
		return &edited{path: path}, nil
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return &edited{path: path}, nil
	case err != nil:
		return nil, err
	}
	if within != "" && !encloses(within, dir) {
		return nil, errNotOperators
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		if f.dryRun {
			return &edited{path: path}, nil
		}
		return nil, err
	}
	name := filepath.Base(target)
	out := &edited{path: filepath.Join(dir, name), root: root, name: name}
	if !exists {
		// Nothing to check and nothing to keep: the caller creates it, and creation
		// is where ownership is faramir's to set.
		return out, nil
	}
	info, err := out.stat()
	switch {
	// A path that cannot be read is a different problem from one somebody else
	// owns, and saying the wrong one sends an operator after the wrong fix.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		out.close()
		return &edited{path: path}, nil
	case errors.Is(err, os.ErrNotExist):
		out.close()
		return nil, errNotOperators
	case err != nil:
		out.close()
		return nil, err
	case !info.Mode().IsRegular():
		out.close()
		return nil, errNotOperators
	}
	switch wrong, err := wrongOwner(info, uid, keep); {
	case err != nil, wrong:
		out.close()
		if err != nil {
			return nil, err
		}
		return nil, errNotOperators
	}
	out.info = info
	return out, nil
}

// stat asks the descriptor where there is one, so what is checked is what is
// written rather than whatever the path names by then.
func (e *edited) stat() (os.FileInfo, error) {
	if e.root != nil {
		return e.root.Stat(e.name)
	}
	return os.Stat(e.path)
}

// writeEdited writes data where editedFile said, through the descriptor where
// one was opened.
func (f fsys) writeEdited(e *edited, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	if e.root == nil {
		return f.writeFile(e.path, data, mode, uid, gid)
	}
	return f.writeInto(e.root, e.name, data, mode, uid, gid, unread())
}

// writeInto is writeFile relative to an open directory: same comparison, same
// temp-and-rename, and no path resolved twice. The temp is created O_EXCL, so
// one already sitting there is an error rather than something to truncate.
func (f fsys) writeInto(root *os.Root, name string, data []byte, mode os.FileMode,
	uid, gid int, prior priorState) (bool, error) {
	current, err := root.ReadFile(name)
	if err == nil && bytes.Equal(current, data) {
		info, statErr := root.Stat(name)
		if statErr != nil {
			return false, statErr
		}
		wrong, ownErr := wrongOwner(info, uid, gid)
		if ownErr != nil {
			return false, ownErr
		}
		if info.Mode().Perm() == mode.Perm() && !wrong {
			return false, nil
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if f.dryRun {
		return true, nil
	}
	tmp := name + ".faramir-tmp"
	handle, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if errors.Is(err, os.ErrExist) {
		// O_EXCL, so one already there is not something to truncate: it is either
		// a run in progress or what a killed one left, and neither is this write's
		// to overwrite. Named through the root's own path and wrapped: the bare
		// error says a file exists without saying which, and tmp is a base name
		// whose directory is the one thing an operator cannot guess.
		return false, fmt.Errorf("%s is already there, so nothing was written: it is "+
			"the temporary file a write goes through, so another faramir command is "+
			"writing this file, or one was interrupted while it did. Run them one at "+
			"a time; delete it if none is running: %w",
			filepath.Join(root.Name(), tmp), err)
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", tmp, err)
	}
	// Removed only where the rename did not take it. After a successful rename the
	// name is free, and another writer's O_EXCL open may already have claimed it:
	// removing it then deletes that run's temporary file, and its chmod fails with
	// an ENOENT about a path it created itself.
	renamed := false
	defer func() {
		if !renamed {
			_ = root.Remove(tmp)
		}
	}()
	// Asked while the temporary name is held, which is what makes it decide
	// something: O_EXCL admits one writer at a time, so a second either fails
	// above or gets here after the first has renamed and sees the change. Asked
	// before the write rather than after, so nothing is written for a rename that
	// is not going to happen.
	if err := unchangedFrom(root, name, prior); err != nil {
		return false, err
	}
	if _, err := handle.Write(data); err != nil {
		_ = handle.Close()
		return false, err
	}
	if err := handle.Close(); err != nil {
		return false, err
	}
	// The open applied the umask; these do not.
	if err := root.Chmod(tmp, mode); err != nil {
		return false, err
	}
	if uid != keep || gid != keep {
		if err := root.Lchown(tmp, uid, gid); err != nil {
			return false, err
		}
	}
	if err := root.Rename(tmp, name); err != nil {
		return false, err
	}
	renamed = true
	return true, nil
}

// priorState is what the caller found when it read the file it is now writing
// back. Two things, and they are refused differently: a file something else
// rewrote, and a file something else created where this caller found none.
//
// Absence has to be one of them. A record's first write has no digest to
// expect, so treating "nothing to compare" as "nothing to check" left two
// concurrent first runs both writing and one entry lost with no error, which
// is the window the digest exists to close.
type priorState struct {
	// digest is the sha256 of what was there, nil where nothing was.
	digest []byte
	// read is whether the caller looked at all. A write that is not an edit of
	// anything sets neither field and is refused for nothing, which is most of
	// them.
	read bool
}

// unread is the state of a write that is not an edit: nothing was read, so
// nothing is expected.
func unread() priorState { return priorState{} }

// after is the state of a caller that read the file, digest or not.
func after(digest []byte) priorState { return priorState{digest: digest, read: true} }

// unchangedFrom refuses a write onto a file something else has written, or
// created, since the caller read.
func unchangedFrom(root *os.Root, name string, prior priorState) error {
	if !prior.read {
		return nil
	}
	body, err := root.ReadFile(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Gone, or never there. Either matches a caller that read nothing.
		if prior.digest == nil {
			return nil
		}
	case err != nil:
		return err
	case prior.digest == nil:
		// The caller read no file and one is here now: another run created it,
		// and renaming over it would take whatever it wrote.
		return fmt.Errorf("%s was created while this was working on it, so nothing "+
			"was written: another faramir command wrote it first. Run them one at a "+
			"time, then run this again", filepath.Join(root.Name(), name))
	default:
		sum := sha256.Sum256(body)
		if bytes.Equal(sum[:], prior.digest) {
			return nil
		}
	}
	return fmt.Errorf("%s changed while this was working on it, so nothing was "+
		"written: another faramir command edited it. Run them one at a time, then "+
		"run this again", filepath.Join(root.Name(), name))
}

// ownerOf is a file's uid and gid, or keep for both where they cannot be read.
func ownerOf(info os.FileInfo) (int, int) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return keep, keep
	}
	return int(st.Uid), int(st.Gid)
}

// writeFile writes data when the file is absent or differs, compared by content
// so an unchanged re-run reports nothing.
//
// Through a descriptor opened on the parent, so the directory is resolved once
// and the temp and the rename cannot land in two different places: some of what
// this writes sits in the agent account's home or in an enrolled tree, which an
// account other than root can replace while a run is in progress.
func (f fsys) writeFile(path string, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		// A dry run creates no directories, so the parent of a file it would create
		// is not there to open. Reported as a write.
		if f.dryRun {
			return true, nil
		}
		return false, err
	}
	defer func() { _ = root.Close() }()
	return f.writeInto(root, filepath.Base(path), data, mode, uid, gid, unread())
}

// writeFileExpecting is writeFile for a file the caller read and is writing
// back: the write is refused where something else has written it since, and
// where something else created one the caller did not find. expect is the
// digest of what was read, nil where nothing was there.
func (f fsys) writeFileExpecting(path string, data []byte, mode os.FileMode,
	uid, gid int, expect []byte) (bool, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		// The directory a record lives in is the config directory, which every
		// caller of this has already created. Reported as a write for a dry run,
		// as writeFile does.
		if f.dryRun {
			return true, nil
		}
		return false, err
	}
	defer func() { _ = root.Close() }()
	return f.writeInto(root, filepath.Base(path), data, mode, uid, gid, after(expect))
}

// copyFile writes src's contents to dst under dst's own mode and ownership.
func (f fsys) copyFile(src, dst string, mode os.FileMode, uid, gid int) (bool, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	return f.writeFile(dst, data, mode, uid, gid)
}

// missingAncestors lists every directory MkdirAll would have to create, from
// the shallowest down to path itself.
func missingAncestors(path string) []string {
	var missing []string
	for at := path; ; at = filepath.Dir(at) {
		if exists(at) {
			break
		}
		missing = append([]string{at}, missing...)
		if parent := filepath.Dir(at); parent == at {
			break
		}
	}
	return missing
}

// exists reports whether a path is there, following symlinks.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// probe is exists with a third answer: known is false when the question needs
// more privilege than the caller has, which only happens under a dry run. "not
// there" for a key behind a 0700 directory would read as a key about to be
// regenerated.
func probe(path string) (present, known bool) {
	switch _, err := os.Stat(path); {
	case err == nil:
		return true, true
	case errors.Is(err, os.ErrNotExist):
		return false, true
	default:
		return false, false
	}
}

func chown(path string, uid, gid int) error {
	if uid == keep && gid == keep {
		return nil
	}
	return os.Lchown(path, uid, gid)
}

func wrongOwner(info os.FileInfo, uid, gid int) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("cannot read ownership")
	}
	if uid != keep && int(stat.Uid) != uid {
		return true, nil
	}
	return gid != keep && int(stat.Gid) != gid, nil
}

func deviceOf(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Dev
}

// lookupUser and lookupGroup resolve a name to an id, so a missing account is
// reported as itself rather than as whatever the next syscall returned.
func lookupUser(name string) (int, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("no such user %q: %w", name, err)
	}
	return strconv.Atoi(entry.Uid)
}

// lookPathOr resolves a program on PATH, falling back to a conventional path so
// a host that lacks it gets a config naming where it should be. The broker
// refuses to start when the binary is not there.
func lookPathOr(program, fallback string) string {
	if path, err := exec.LookPath(program); err == nil {
		return path
	}
	return fallback
}

// primaryGroup resolves an account's own group, returning both the gid and the
// name. Two lookups rather than one on the account name, which would find a
// group that merely shares the name.
func primaryGroup(account string) (int, string, error) {
	entry, err := user.Lookup(account)
	if err != nil {
		return 0, "", fmt.Errorf("no such user %q: %w", account, err)
	}
	gid, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return 0, "", err
	}
	group, err := user.LookupGroupId(entry.Gid)
	if err != nil {
		return 0, "", fmt.Errorf("%s has no group %s: %w", account, entry.Gid, err)
	}
	return gid, group.Name, nil
}

func lookupGroup(name string) (int, error) {
	entry, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("no such group %q: %w", name, err)
	}
	return strconv.Atoi(entry.Gid)
}

// userExists and groupExists answer without turning a missing entry into an
// error.
func userExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func groupExists(name string) bool {
	_, err := user.LookupGroup(name)
	return err == nil
}
