package hostfs

// Reading the host back: what is there, who owns it, and which accounts and
// groups resolve. Nothing here writes.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// missingAncestors lists every directory MkdirAll would have to create, from
// the shallowest down to path itself.
func missingAncestors(path string) []string {
	var missing []string
	for at := path; ; at = filepath.Dir(at) {
		if Exists(at) {
			break
		}
		missing = append([]string{at}, missing...)
		if parent := filepath.Dir(at); parent == at {
			break
		}
	}
	return missing
}

// Exists reports whether a path is there, following symlinks.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SymlinkTarget is the file a symlink points at, and false for a path that is
// not one. Only the last component is read, through as many links as it takes
// to reach a file: a symlinked ancestor (/home to /data/home) is part of the
// spelling every path on the host shares, and resolving it would make a second
// entry out of a path that names its file directly.
func SymlinkTarget(path string) (string, bool) {
	target := path
	// The kernel's own limit on a chain of links, past which a path does not
	// open at all.
	for range 40 {
		info, err := os.Lstat(target)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			if target == path {
				return "", false
			}
			return target, true
		}
		next, err := os.Readlink(target)
		if err != nil {
			return "", false
		}
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(target), next)
		}
		target = filepath.Clean(next)
	}
	return "", false
}

// Probe is exists with a third answer: known is false when the question needs
// more privilege than the caller has, which only happens under a dry run. "not
// there" for a key behind a 0700 directory would read as a key about to be
// regenerated.
func Probe(path string) (present, known bool) {
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
	if uid == Keep && gid == Keep {
		return nil
	}
	return os.Lchown(path, uid, gid)
}

func WrongOwner(info os.FileInfo, uid, gid int) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("cannot read ownership")
	}
	if uid != Keep && int(stat.Uid) != uid {
		return true, nil
	}
	return gid != Keep && int(stat.Gid) != gid, nil
}

func deviceOf(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Dev
}

// LookupUser and lookupGroup resolve a name to an id, so a missing account is
// reported as itself rather than as whatever the next syscall returned.
func LookupUser(name string) (int, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("no such user %q: %w", name, err)
	}
	return strconv.Atoi(entry.Uid)
}

// LookPathOr resolves a program on PATH, falling back to a conventional path so
// a host that lacks it gets a config naming where it should be. The broker
// refuses to start when the binary is not there.
func LookPathOr(program, fallback string) string {
	if path, err := exec.LookPath(program); err == nil {
		return path
	}
	return fallback
}

// PrimaryGroup resolves an account's own group, returning both the gid and the
// name. Two lookups rather than one on the account name, which would find a
// group that merely shares the name.
func PrimaryGroup(account string) (int, string, error) {
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

func LookupGroup(name string) (int, error) {
	entry, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("no such group %q: %w", name, err)
	}
	return strconv.Atoi(entry.Gid)
}

// UserExists and groupExists answer without turning a missing entry into an
// error.
func UserExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func GroupExists(name string) bool {
	_, err := user.LookupGroup(name)
	return err == nil
}

// Encloses compares path elements, so /home/andornaut2 is not inside
// /home/andornaut.
func Encloses(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// InGroup reports membership, primary or supplementary.
func InGroup(name, group string) (bool, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return false, err
	}
	// A group that does not exist is one nobody is in, which is the dry-run
	// case.
	target, err := user.LookupGroup(group)
	if err != nil {
		return false, nil //nolint:nilerr // an absent group is an answer, not a failure
	}
	ids, err := entry.GroupIds()
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, target.Gid), nil
}

// HomeIsMounted reports whether an encrypted home has been unlocked. Writing
// into one before its owner logs in lands in the unencrypted backing directory,
// where it is shadowed the moment the home mounts. A mounted filesystem sits
// on a different device from the directory it covers, which is what this
// compares; mountpoint(1) is not on every host, and its absence would read as
// "not mounted".
func HomeIsMounted(home string) bool {
	info, err := os.Stat(home)
	if err != nil {
		return false
	}
	parent, err := os.Stat(filepath.Dir(home))
	if err != nil {
		return false
	}
	return deviceOf(info) != deviceOf(parent)
}

// LooksEncrypted reports whether a home is one of the ecryptfs layouts, which
// are the ones that are a different directory before login.
func LooksEncrypted(home string) bool {
	if _, err := os.Stat(filepath.Join("/home/.ecryptfs", filepath.Base(home))); err == nil {
		return true
	}
	_, err := os.Stat(filepath.Join(home, ".ecryptfs"))
	return err == nil
}
