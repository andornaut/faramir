package broker

// Where a brokered sudo starts. The executor forks as its own uid, and a fork
// with a working directory has to enter it as that uid before the exec. A tree
// that was never enrolled is one the executor cannot enter, so a sudo started
// there would fail before any question was asked, though root needs nothing of
// the executor's to enter it. A sudo that will run a command as root is started
// in / instead and told where to go with -D, which sudo applies as root after
// the approval. The grant's runcwd=* (CWD=* under sudo-rs) is what lets the
// executor pass -D.

import (
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// sudoChdirRoot is where a rewritten sudo starts: a directory every uid can
// enter.
const sudoChdirRoot = "/"

// sudoOption is what one of sudo's options means for the rewrite. The zero
// value is an option this does not know, which leaves the argv alone.
type sudoOption int

const (
	// optFlag takes no argument.
	optFlag sudoOption = iota + 1
	// optValue takes an argument: joined, or the next word.
	optValue
	// optKeep leaves the argv as the caller sent it: a directory already chosen
	// (-D), one sudo chooses itself (-i, -s), a root that moves (-R), or a mode
	// that runs no command or that sudo-rs refuses -D with (-e, -l, -v, -K, -V,
	// -h).
	optKeep
)

// sudoShort is sudo's short options, by letter.
var sudoShort = map[byte]sudoOption{
	'A': optFlag, 'b': optFlag, 'B': optFlag, 'E': optFlag, 'H': optFlag,
	'k': optFlag, 'n': optFlag, 'N': optFlag, 'P': optFlag, 'S': optFlag,
	'C': optValue, 'g': optValue, 'p': optValue, 'r': optValue, 't': optValue,
	'T': optValue, 'u': optValue, 'U': optValue,
	'D': optKeep, 'i': optKeep, 's': optKeep, 'R': optKeep, 'e': optKeep,
	'l': optKeep, 'v': optKeep, 'K': optKeep, 'V': optKeep, 'h': optKeep,
}

// sudoLong is sudo's long options. An abbreviation is not here: the original
// sudo accepts one and sudo-rs does not, so it is left alone like any other
// unknown option.
var sudoLong = map[string]sudoOption{
	"askpass": optFlag, "background": optFlag, "bell": optFlag,
	"preserve-env": optFlag, "set-home": optFlag, "reset-timestamp": optFlag,
	"non-interactive": optFlag, "no-update": optFlag, "preserve-groups": optFlag,
	"stdin":      optFlag,
	"close-from": optValue, "command-timeout": optValue, "group": optValue,
	"other-user": optValue, "prompt": optValue, "role": optValue,
	"type": optValue, "user": optValue,
	"chdir": optKeep, "chroot": optKeep, "edit": optKeep, "help": optKeep,
	"host": optKeep, "list": optKeep, "login": optKeep, "remove-timestamp": optKeep,
	"shell": optKeep, "validate": optKeep, "version": optKeep,
}

// sudoPrefix is what sudo's option prefix says, as far as the rewrite needs.
type sudoPrefix struct {
	// rewritable is false where an option rules the rewrite out or could not be
	// read, and where no command follows the options.
	rewritable  bool
	user, group string
}

// take records the argument of an option that decides whom the command runs
// as. Every other option's argument is skipped.
func (p *sudoPrefix) take(option, value string) {
	switch option {
	case "u", "user":
		p.user = value
	case "g", "group":
		p.group = value
	}
}

// parseSudoPrefix reads argv[1:] up to `--` or the first word that is not an
// option, which is the command. An option's argument is never read as the
// command.
func parseSudoPrefix(argv []string) sudoPrefix {
	var p sudoPrefix
	i := 1
	// next is the word after argv[i], consumed as an option's argument.
	next := func() (string, bool) {
		if i+1 >= len(argv) {
			return "", false
		}
		i++
		return argv[i], true
	}
	for ; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			i++
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			break
		}
		if long, ok := strings.CutPrefix(arg, "--"); ok {
			name, value, joined := strings.Cut(long, "=")
			kind := sudoLong[name]
			// --preserve-env=list is the one flag that takes a value, and only
			// joined to it.
			if kind == optFlag && (!joined || name == "preserve-env") {
				continue
			}
			if kind != optValue {
				return p
			}
			if !joined {
				word, more := next()
				if !more {
					return p
				}
				value = word
			}
			p.take(name, value)
			continue
		}
		for j := 1; j < len(arg); j++ {
			kind := sudoShort[arg[j]]
			if kind == optFlag {
				continue
			}
			if kind != optValue {
				return p
			}
			// The rest of the word is the argument, or the next word is.
			value := arg[j+1:]
			if value == "" {
				word, more := next()
				if !more {
					return p
				}
				value = word
			}
			p.take(arg[j:j+1], value)
			break
		}
	}
	p.rewritable = i < len(argv)
	return p
}

// sudoChdir returns argv with `-D cwd` after argv[0] and true when argv is a
// sudo that runs a command as root, and argv unchanged and false otherwise.
// argv[0] is not read: whether the program is the host's sudo is the caller's
// question.
//
// A command run as another account is left alone: -D makes sudo enter the
// directory as that account, which can be refused where inheriting it works.
// So is -g without -u, which runs the command as the invoking account.
func sudoChdir(cwd string, argv []string) ([]string, bool) {
	p := parseSudoPrefix(argv)
	switch {
	case !p.rewritable:
		return argv, false
	case p.user != "" && p.user != "root" && p.user != "#0":
		return argv, false
	case p.user == "" && p.group != "":
		return argv, false
	}
	out := make([]string, 0, len(argv)+2)
	out = append(out, argv[0], "-D", cwd)
	return append(out, argv[1:]...), true
}

// isHostSudo reports whether a resolved program is the sudo a bare `sudo`
// resolves to on [command.env] PATH, the PATH the child gets. Resolved the same
// way, so a symlink such as an alternatives link compares by its target, and a
// file named sudo elsewhere is not taken for it.
func isHostSudo(execCfg config.CommandConfig, argv0Path string) bool {
	sudo, err := resolveProgram("sudo", sudoChdirRoot, execCfg)
	return err == nil && sudo == argv0Path
}

// execTarget is the argv and directory the executor is given, and the
// directory passed to -D, "" where the command runs as sent. A sudo is
// rewritten only on a run with a run id: without one it cannot be approved, and
// the executor's own refusal to enter the cwd is the more useful failure.
func execTarget(execCfg config.CommandConfig, runID, argv0Path, cwd string,
	cmd []string) (argv []string, dir, chdir string) {
	argv = append([]string{argv0Path}, cmd[1:]...)
	if runID == "" || !isHostSudo(execCfg, argv0Path) {
		return argv, cwd, ""
	}
	if rewritten, ok := sudoChdir(cwd, argv); ok {
		return rewritten, sudoChdirRoot, cwd
	}
	return argv, cwd, ""
}
