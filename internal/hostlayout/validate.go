package hostlayout

// What a layout is held to before anything is written from it.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// Validate rejects the placements that install cleanly and then do not work,
// before anything is written.
func (l Layout) Validate() error {
	// The secrets and the key are under it, so checking the config directory
	// checks every path an operator can move.
	dir := l.ConfigDir
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("config dir must be an absolute path: %s", dir)
	}
	// systemd word-splits Environment= and expands % specifiers in it, so a path
	// holding either reaches the daemons truncated or not at all.
	if strings.ContainsAny(dir, " \t") {
		return fmt.Errorf("config dir must not contain whitespace: %s", dir)
	}
	if strings.Contains(dir, "%") {
		return fmt.Errorf("config dir must not contain '%%': %s", dir)
	}
	if under := privateTmpDir(dir); under != "" {
		return fmt.Errorf("config dir must not be under %s: %s\n"+
			"Every unit runs with PrivateTmp=true, so each daemon sees its own %s "+
			"and none of them would find the files this run wrote. Name a directory "+
			"outside it (the default is %s)", under, dir, under, DefaultConfigDir)
	}
	// Blocked here rather than left to whatever renders it: these paths are
	// interpolated into the agents' JSON settings, into config.toml and into the
	// deny patterns, and each format escapes a different set. A settings file the
	// agent cannot parse reads as an enrolment that worked with every rule in it
	// missing.
	if name, bad := hasControlChar(dir); bad {
		return fmt.Errorf("config dir must not contain a control character (%s): %q",
			name, dir)
	}
	if name, bad := hasControlChar(l.SSHKey); bad {
		return fmt.Errorf("ssh key path must not contain a control character (%s): %q",
			name, l.SSHKey)
	}
	for name, account := range map[string]string{
		"group":         l.ClientGroup,
		"broker user":   l.BrokerUser,
		"keeper user":   l.KeeperUser,
		"exec user":     l.ExecUser,
		"agent user":    l.AgentUser,
		"secrets group": l.SecretsGroup,
	} {
		// The agent user and the secrets group are named after the rest because
		// they are rendered later, not because they are checked less: both reach
		// config.toml, and the agent user reaches the environment file a brokered
		// command's sudo is given.
		if account == "" && (name == "agent user" || name == "secrets group") {
			continue // filled in by the step that resolves it, or not used
		}
		if account == "" {
			return fmt.Errorf("%s must be named", name)
		}
		if strings.ContainsAny(account, " \t:,") {
			return fmt.Errorf("%s is not a usable account name: %q", name, account)
		}
		// Every one of these is written into a file that is read a line at a time:
		// config.toml, the logrotate rule, and the environment file pam_env hands
		// to a brokered command's sudo. A newline in a name ends the line it was
		// written into and makes the rest of it a directive of its own, in a file
		// that decides what root is given.
		if bad, found := hasControlChar(account); found {
			return fmt.Errorf("%s must not contain a control character (%s): %q",
				name, bad, account)
		}
	}
	// The three uids are the boundaries: two of them sharing a name is an install
	// where the executor's uid holds the age key or the audit log.
	seen := map[string]string{}
	for name, account := range map[string]string{
		"broker user": l.BrokerUser,
		"keeper user": l.KeeperUser,
		"exec user":   l.ExecUser,
	} {
		if other, dup := seen[account]; dup {
			return fmt.Errorf("%s and %s are both %q. Each daemon needs its own "+
				"account: separate uids are what keep the age key, the audit log "+
				"and brokered commands apart", other, name, account)
		}
		seen[account] = name
	}
	// And the operator is not one of them. Separate from the loop above, which is
	// about the three daemons keeping their boundary from each other: this is
	// about the boundary that makes the whole arrangement work, a brokered command
	// running as an account holding nothing the agent's account holds. An operator
	// who is also a daemon leaves none of it, every injected value sitting in a
	// process of the operator's own uid and every path refused to the agent being
	// that account's to read.
	//
	// Empty is left alone here as it is above, the step that resolves it not
	// having run on every path that builds a layout.
	if l.AgentUser != "" {
		for _, daemon := range []struct{ role, flag, account string }{
			{"broker", BrokerUserFlag, l.BrokerUser},
			{"keeper", KeeperUserFlag, l.KeeperUser},
			{"executor", ExecUserFlag, l.ExecUser},
		} {
			if l.AgentUser == daemon.account {
				return fmt.Errorf("--agent-user %s is the account the %s runs as. The "+
					"agent and that daemon would share a uid, so the agent could read "+
					"everything a brokered command holds. Name a different account, "+
					"or move the daemon with %s",
					l.AgentUser, daemon.role, daemon.flag)
			}
		}
	}
	return l.validateNotifyCommand()
}

// PrivateTmp is what PrivateTmp= gives every unit its own copy of. Both
// hierarchies, since the directive covers both.
//
// A variable rather than a constant for this package's own tests, which point
// an install at a directory made by t.TempDir(): that lands under TMPDIR, which
// is the very thing this refuses on a real host, so a test asserting on some
// other refusal would meet this one first. Unexported and cleared only by the
// helper those tests share, so nothing outside can turn the check off.
var PrivateTmp = []string{"/tmp", "/var/tmp"}

// privateTmpDir is the temporary hierarchy a path sits in, or "" for a path
// outside both.
//
// Refused rather than left to fail at the daemons' next start. PrivateTmp=true
// gives every unit a /tmp and a /var/tmp of its own, so a config directory
// there is written by an install running in the host's namespace and looked for
// by three daemons that each have a different one. What the operator sees is an
// install reporting every step done and a broker that will not start, with the
// directory sitting on disk exactly where they put it.
//
// Both hierarchies, since PrivateTmp= covers both. The check is on the path
// rather than on the filesystem under it: a bind mount elsewhere is somebody's
// deliberate arrangement, and what breaks the install is the unit directive
// reading these two names.
func privateTmpDir(dir string) string {
	for _, tmp := range PrivateTmp {
		if dir == tmp || strings.HasPrefix(dir, tmp+"/") {
			return tmp
		}
	}
	return ""
}

// hasControlChar reports whether a path holds a character no rendered format
// takes literally, naming it so the refusal says which. DEL as well as the C0
// range, and an invalid UTF-8 byte with them: ranging over a string yields
// U+FFFD for one, which is not what the operator typed.
func hasControlChar(text string) (string, bool) {
	for _, r := range text {
		switch {
		case r == utf8.RuneError:
			return "an invalid UTF-8 byte", true
		case r < 0x20 || r == 0x7f:
			return fmt.Sprintf("U+%04X", r), true
		}
	}
	return "", false
}

// notifySource names where the announcement being validated came from, so a
// refusal points at what the operator would change: the flag when they typed
// one, and the installed config when this run kept what was already there. Both
// refusals name the flag as the way to change it either way.
func (l Layout) notifySource() string {
	if l.NotifyAdopted {
		return "the installed [sudo] notify_command"
	}
	return "--notify-command"
}

// validateNotifyCommand holds the announcement to what the loader will accept,
// so a bad one is refused before anything is written rather than at the
// daemon's next start. The rules are the loader's: see
// config.loadSudo.
func (l Layout) validateNotifyCommand() error {
	if len(l.NotifyCommand) == 0 {
		return nil
	}
	if !l.AllowSudo {
		return fmt.Errorf("--notify-command announces a pending escalation, but this "+
			"install grants no sudo, so there is nothing to announce. Pass --allow-sudo "+
			"as well, or drop --notify-command (%s)",
			strings.Join(l.NotifyCommand, " "))
	}
	if !slices.ContainsFunc(l.NotifyCommand, func(arg string) bool {
		return strings.Contains(arg, "{prompt}") || strings.Contains(arg, "{id}")
	}) {
		return fmt.Errorf("%s names neither {prompt} nor {id}, so it "+
			"would announce that something is waiting without saying what: %s",
			l.notifySource(), strings.Join(l.NotifyCommand, " "))
	}
	// Absolute by the time this runs, Options.layout resolving argv[0] on PATH.
	// Checked rather than assumed: a name that resolved to nothing would reach
	// the config as itself and be looked up again by the broker's PATH.
	if !filepath.IsAbs(l.NotifyCommand[0]) {
		return fmt.Errorf("%s %q is not on PATH and is not an absolute path. "+
			"It runs as the account that holds every decrypted value, so name the "+
			"program by its absolute path",
			l.notifySource(), l.NotifyCommand[0])
	}
	// And it has to be there: a path written out by hand is taken as given, so a
	// typo would reach the config and fail at the --check that follows, after
	// every file was written.
	info, err := os.Stat(l.NotifyCommand[0])
	if err != nil {
		return fmt.Errorf("%s %q does not exist (%v). Install it, or name "+
			"a program that exists with --notify-command. Without it no pending "+
			"escalation would be announced", l.notifySource(), l.NotifyCommand[0], err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s %q is not an executable file: the broker "+
			"runs it directly, not through a shell",
			l.notifySource(), l.NotifyCommand[0])
	}
	return nil
}
