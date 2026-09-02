// Package asaccount answers what one account can reach, by being that account.
//
// A mode says what should happen; this says what does. A filesystem that
// ignores the mode, a socket regrouped after it was written, an account added
// to the shared group by hand: each leaves the written answer intact and the
// real one different. So the question is put through runuser as the uid it is
// about, which is what makes root a requirement here, root bypassing file modes
// being the reason a check run as root would answer yes to everything.
//
// access(2) is asked through faramir's own binary rather than the host's
// `test`: access(2) answers for the calling process, and some `test`
// implementations ignore supplementary group membership, which makes every
// group-based finding wrong in both directions.
package asaccount

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/runcmd"
)

// Output runs a command as another account and reports its output. An empty
// account is refused rather than passed on: `runuser -u -- cmd` takes the "--"
// as the account name and fails, which every caller here would report as a
// boundary that does not hold.
func Output(account string, args ...string) (string, error) {
	if account == "" {
		return "", errors.New("no account named, so there is nobody to ask")
	}
	// Bounded: a probe is a question, and one that hangs holds the whole
	// examination on the host being diagnosed. Generous, a brokered probe
	// carrying a real command inside it.
	return runcmd.OutputWithin(2*time.Minute, "runuser", append([]string{"-u", account, "--"}, args...)...)
}

// CanRead and CanWrite answer access(2) as that account. Connecting to a unix
// socket needs write, so a socket left 0620 passes a read check.
//
// Through faramir's own binary rather than the host's `test`: access(2) answers
// for the calling process, and some `test` implementations (uutils) ignore
// supplementary group membership, which makes every group-based finding wrong
// in both directions. See cmd/faramir/access.go.
func CanRead(account, path string) bool {
	_, err := Output(account, SelfPath(), "access", "--read", path)
	return err == nil
}

func CanWrite(account, path string) bool {
	_, err := Output(account, SelfPath(), "access", "--write", path)
	return err == nil
}

// CanTraverse asks the question a directory answers with its execute bit:
// whether paths under it can be reached at all. Separate from CanRead because
// the two are independent, a directory being listable without being passable
// and passable without being listable.
func CanTraverse(account, path string) bool {
	_, err := Output(account, SelfPath(), "access", "--execute", path)
	return err == nil
}

// SelfPath is the binary to re-run as another account: this process's own, so a
// doctor run from a build that is not the installed one asks itself. The
// target account has to be able to execute it, which a build in an operator's
// home may not be; DefaultBinDir is the fallback.
func SelfPath() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return filepath.Join(hostlayout.DefaultBinDir, "faramir")
	}
	return exe
}

// missing is what Owns and OwnsWithGroup report for a path that is not there,
// and what a test compares against.
const missing = "missing"

// Owns reports a file's mode and owner as "%04o account", or "missing". The
// owner alone: the age key is 0400 and the audit log 0600, so no group bit is
// set and which group owns them decides nothing.
func Owns(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return missing
	}
	return fmt.Sprintf("%04o %s", info.Mode().Perm(), ownerName(info))
}

// OwnsWithGroup is Owns plus the group, for the callers that compare both:
// a message naming only the owner would carry a remedy that cannot clear the
// condition it printed.
func OwnsWithGroup(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return missing
	}
	return fmt.Sprintf("%04o %s:%s", info.Mode().Perm(), ownerName(info), GroupName(info))
}

// BlockingDir returns the first directory on the way to path that account
// cannot enter, or "" when every one of them is enterable. Answered from the
// modes rather than by asking the account: doctor is root here, so it can read
// what an unprivileged probe would only be refused by, and a refusal names no
// directory of its own.
func BlockingDir(account, path string) string {
	who, err := user.Lookup(account)
	if err != nil {
		return ""
	}
	uid, err := strconv.Atoi(who.Uid)
	if err != nil {
		return ""
	}
	if uid == 0 {
		return ""
	}
	groups := map[int]bool{}
	if ids, err := who.GroupIds(); err == nil {
		for _, id := range ids {
			if gid, err := strconv.Atoi(id); err == nil {
				groups[gid] = true
			}
		}
	}
	// Root down to the file's own directory. The file's own mode is not this
	// check: a directory that cannot be entered refuses it whatever it says.
	var dirs []string
	for at := filepath.Dir(path); ; at = filepath.Dir(at) {
		dirs = append([]string{at}, dirs...)
		if at == "/" || at == "." {
			break
		}
	}
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			return ""
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ""
		}
		if !enterable(uid, groups, info.Mode().Perm(), int(st.Uid), int(st.Gid)) {
			return dir
		}
	}
	return ""
}

// enterable reports whether a uid carrying these groups may enter a directory
// of this mode and ownership. One class only, the way the kernel decides it:
// an owner is judged by the owner bit and never falls back to the group's, so
// a directory owned by the account with mode 0600 refuses it however open the
// group bits are.
func enterable(uid int, groups map[int]bool, mode os.FileMode, owner, group int) bool {
	switch {
	case owner == uid:
		return mode&0o100 != 0
	case groups[group]:
		return mode&0o010 != 0
	}
	return mode&0o001 != 0
}

// Holds is hostfs.InGroup with the error folded in: an unknown account is in
// no group.
func Holds(account, group string) bool {
	member, err := hostfs.InGroup(account, group)
	return err == nil && member
}

// ownerName is the account a file belongs to, or the numeric uid.
func ownerName(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown"
	}
	uid := strconv.Itoa(int(stat.Uid))
	if account, err := user.LookupId(uid); err == nil {
		return account.Username
	}
	return uid
}

// GroupName is the group a file belongs to, or the numeric gid.
func GroupName(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown"
	}
	gid := strconv.Itoa(int(stat.Gid))
	if group, err := user.LookupGroupId(gid); err == nil {
		return group.Name
	}
	return gid
}

// GroupNameOf is an account's own group, by name, for a remedy a reader pastes
// into a shell: an account adopted by --broker-user may have a group named
// something else, and a chgrp naming the account fails with "invalid group".
// Falls back to the account name, so the remedy is never printed with an empty
// field.
func GroupNameOf(account string) string {
	if _, name, err := hostfs.PrimaryGroup(account); err == nil {
		return name
	}
	return account
}

// GroupOf is the group name owning a path.
func GroupOf(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: cannot read ownership", path)
	}
	group, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid)))
	if err != nil {
		return "", err
	}
	return group.Name, nil
}
