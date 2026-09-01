package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/fserr"
)

// The environment a child editor is started with. A fixed PATH so the editor
// found is one on the system's own, and a UTF-8 locale so a value carrying
// anything but ASCII survives the round trip through it.
const (
	envPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	envLANG = "LANG=C.UTF-8"
)

// Editors are tried in order when none is given. Absolute paths only:
// "sensible-editor" and "editor" resolve through files the operator can write.
var Editors = []string{
	"/usr/bin/vim",
	"/usr/bin/vi",
	"/bin/vi",
	"/usr/bin/nano",
	"/bin/nano",
}

// ResolveEditor picks the editor and holds every source to the same check. In
// order: --editor, $VISUAL, $EDITOR, then the first of editors that passes.
//
// The variables are read because the check, not the source, is what makes a
// program safe to run as root over the decrypted store: an account that cannot
// write the binary or any directory above it cannot change what runs, cannot
// pass it an argument, and cannot reach it through a config file either, the
// child's HOME being the tmpfs. Under plain sudo env_reset drops both
// variables, so on a stock host the built-in list is what decides.
func ResolveEditor(requested string) (string, error) {
	for _, source := range []struct{ named, value string }{
		{"--editor", requested},
		{"$VISUAL", os.Getenv("VISUAL")},
		{"$EDITOR", os.Getenv("EDITOR")},
	} {
		if source.value == "" {
			continue
		}
		// Refused rather than passed over: a named editor that cannot be run is
		// the operator's own setting, and falling through to the list would open
		// the store in an editor they did not ask for and say nothing about it.
		path, err := CheckedEditor(source.value)
		if err != nil {
			return "", fmt.Errorf("%s %w", source.named, err)
		}
		return path, nil
	}
	// The list is held to the check too. A candidate that is simply not installed
	// is not worth reporting; one that is there and cannot be run is the whole
	// answer to "no editor found".
	var refused []string
	for _, candidate := range Editors {
		path, err := CheckedEditor(candidate)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			refused = append(refused, err.Error())
		}
	}
	if len(refused) > 0 {
		return "", fmt.Errorf("no editor here can be run as root: %s",
			strings.Join(refused, "; "))
	}
	return "", fmt.Errorf("no editor found; install one of %s, or name one with "+
		"--editor, $VISUAL or $EDITOR", strings.Join(Editors, ", "))
}

// CheckedEditor resolves one candidate to the absolute path that will be
// exec'd, or says why it cannot be.
//
// Symlinks are resolved first and the resolved path is what runs. Checking one
// path and exec'ing another would leave the links in between deciding it:
// /usr/bin/vi is an alternatives symlink on a Debian host, and the file it
// names is not the one an ownership check of /usr/bin/vi reads.
func CheckedEditor(named string) (string, error) {
	// A bare path, never a command line. "vim -u /somewhere/vimrc" is an ordinary
	// thing to have in $EDITOR, and -u names a file of commands vim runs on
	// startup: passing arguments through would let an account that owns that file
	// choose what root does while every ownership check still passed. A path
	// holding a space is refused with it, which is the safe direction.
	if len(strings.Fields(named)) > 1 {
		return "", fmt.Errorf("%q names arguments, and faramir runs the program "+
			"alone: give the path by itself", named)
	}
	// Absolute, so what runs as root does not depend on an inherited PATH.
	if !filepath.IsAbs(named) {
		return "", fmt.Errorf("%q must be an absolute path", named)
	}
	resolved, err := filepath.EvalSymlinks(named)
	if err != nil {
		return "", fserr.At(named, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fserr.At(resolved, err)
	}
	if reason := UnsafeToRunAsRoot(resolved, info); reason != "" {
		return "", fmt.Errorf("%s: %s", resolved, reason)
	}
	return resolved, nil
}

// UnsafeToRunAsRoot names why this file must not be the editor, or "" if it may
// be. The editor runs as root with the decrypted store open, so a file an
// account other than root can write is that account choosing what runs as root.
//
// Every directory above it counts as much as the file: write on a directory is
// permission to replace what it holds, and write on that directory's parent is
// permission to replace the directory. So the walk runs to /. The path is
// expected to be resolved already, which is what makes stat'ing each ancestor
// the same question the kernel will answer at exec.
func UnsafeToRunAsRoot(path string, info os.FileInfo) string {
	if !info.Mode().IsRegular() {
		return "not a regular file"
	}
	for at := path; ; at = filepath.Dir(at) {
		stat, ok := mustStat(at)
		if !ok {
			return "cannot read the owner of " + at
		}
		if stat.Uid != 0 {
			return fmt.Sprintf("%s belongs to uid %d rather than root, which is the "+
				"account that would then choose what runs as root", at, stat.Uid)
		}
		// Group and other: root owning it is the point, so its own write bit is
		// not a finding. A sticky directory lets only an entry's owner remove it
		// and would be safe, but no editor lives in one and refusing costs
		// nothing.
		if mode := os.FileMode(stat.Mode).Perm(); mode&0o022 != 0 {
			return fmt.Sprintf("%s is %04o: an account that is not root can replace "+
				"what runs here", at, mode)
		}
		if parent := filepath.Dir(at); parent == at {
			return ""
		}
	}
}

func mustStat(path string) (*syscall.Stat_t, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
