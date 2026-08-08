// Package sharetree makes one directory usable by brokered commands.
//
// Two jobs, and only the second is conditional:
//
//	shared     the operator and a brokered command both write there, so the
//	           tree is group-owned and setgid, which with umask 002 keeps them
//	           from fighting over every file either one creates
//	reachable  a home is 0700, so the executor cannot enter a tree inside one
//	           until it has execute access on every directory above it
//
// Nothing in faramir needs a tree of its own: the managed sops files are under
// /etc and a brokered command runs where its caller was.  This exists for the
// operator who wants to run commands somewhere their own uid owns.
//
// The ACL work shells out to setfacl and getfacl rather than linking libacl,
// because the shipped binaries are CGO_ENABLED=0 and there is no ACL support in
// the standard library.
package sharetree

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Options is one run.  Users are the accounts granted traversal, in the order
// they are written into a single ACL entry.
type Options struct {
	Dir      string
	Operator string
	Group    string
	Users    []string
	// Log receives one line per step, already formatted.
	Log func(string)
}

// Share applies both jobs to one directory.
func Share(opts Options) error {
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return err
	}
	owner, err := user.Lookup(opts.Operator)
	if err != nil {
		return fmt.Errorf("no such user %q: %w", opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return fmt.Errorf("no such group %q: %w", opts.Group, err)
	}
	uid, _ := strconv.Atoi(owner.Uid)
	gid, _ := strconv.Atoi(group.Gid)

	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	// MkdirAll applies the umask, and an existing directory keeps whatever mode
	// it had, so the setgid bit is set explicitly either way.
	if err := os.Chmod(dir, 0o2770|os.ModeSetgid); err != nil {
		return err
	}
	if err := shareTree(dir, gid); err != nil {
		return err
	}
	opts.logf("shared %s with %s", dir, opts.Group)

	// Only for a tree inside the operator's home.  Outside the homes the modes
	// already allow it and there is nothing to grant.
	if owner.HomeDir == "" || !within(owner.HomeDir, dir) {
		return nil
	}
	return grantTraversal(owner.HomeDir, dir, opts)
}

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(fmt.Sprintf(format, args...))
	}
}

// within reports whether dir is under home.  Compared as path elements, so
// /home/andornaut2 is not inside /home/andornaut.
func within(home, dir string) bool {
	rel, err := filepath.Rel(home, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func shareTree(root string, gid int) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		// Symlinks carry no useful mode and chowning one would follow it out of
		// the tree.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if err := os.Lchown(path, -1, gid); err != nil {
			return err
		}
		return os.Chmod(path, GroupShared(info.Mode()))
	})
}

// GroupShared is "chmod g+rwX", plus setgid on a directory.
//
// The X is the whole reason this is not a constant: group execute is added to a
// directory, which needs it to be entered, and to a file only when the file was
// already executable for somebody.  Granting it unconditionally would mark every
// ordinary file in the tree executable.
//
// setgid on the directories is what makes the arrangement hold: a file either
// the operator or a brokered command creates inherits the group rather than the
// creator's own, so the other one can still write it.
func GroupShared(mode os.FileMode) os.FileMode {
	out := mode | 0o060
	switch {
	case mode.IsDir():
		out |= 0o010 | os.ModeSetgid
	case mode.Perm()&0o111 != 0:
		out |= 0o010
	}
	return out
}

// Components lists every directory from home down to dir's parent, which are
// the ones needing traversal.  The tree itself is group-owned above, so it is
// not included.
func Components(home, dir string) []string {
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == "." {
		return nil
	}
	parts := strings.Split(rel, string(filepath.Separator))
	out := []string{home}
	at := home
	for _, part := range parts[:len(parts)-1] {
		at = filepath.Join(at, part)
		out = append(out, at)
	}
	return out
}

func grantTraversal(home, dir string, opts Options) error {
	if _, err := exec.LookPath("setfacl"); err != nil {
		opts.logf("WARNING: %s is inside %s and setfacl is missing.", dir, home)
		opts.logf("    Install the acl package, or keep the tree outside the home:")
		opts.logf("    %s cannot reach it as things stand.", opts.Users[0])
		return nil
	}
	spec := make([]string, 0, len(opts.Users))
	for _, u := range opts.Users {
		spec = append(spec, "u:"+u+":x")
	}
	opts.logf("traversal for %s: %s -> %s", strings.Join(opts.Users, " "), home, dir)

	for _, component := range Components(home, dir) {
		// One call granting every account.  On ecryptfs only the first write
		// against an inode lands, so separate calls would drop all but the first
		// and report success for the rest.
		_ = exec.Command("setfacl", "-m", strings.Join(spec, ","), component).Run()

		// Read back rather than trusting the exit status, for the same reason:
		// that filesystem returns 0 and changes nothing once a directory carries
		// an ACL.
		missing := missingEntries(component, opts.Users)
		if len(missing) == 0 {
			continue
		}
		opts.logf("WARNING: %s did not take an ACL entry for %s.",
			component, strings.Join(missing, " "))
		opts.logf("    setfacl reported success; the filesystem dropped it.  An")
		opts.logf("    ecryptfs directory accepts one ACL and no edits, so this")
		opts.logf("    cannot be fixed in place.  Either keep the tree outside the")
		opts.logf("    home, or give this one directory 'chmod o+x' and accept that")
		opts.logf("    every uid can then traverse it.  Note that with umask 002 in")
		opts.logf("    force the files below are 0664, so that opens the home rather")
		opts.logf("    than a path through it.")
		return nil
	}
	return nil
}

func missingEntries(path string, users []string) []string {
	out, err := exec.Command("getfacl", "-p", "--omit-header", path).Output()
	if err != nil {
		return users
	}
	return MissingFrom(string(out), users)
}

// MissingFrom returns the users with no entry in a getfacl listing.
func MissingFrom(acl string, users []string) []string {
	var missing []string
	for _, u := range users {
		if !strings.Contains(acl, "\nuser:"+u+":") && !strings.HasPrefix(acl, "user:"+u+":") {
			missing = append(missing, u)
		}
	}
	return missing
}
