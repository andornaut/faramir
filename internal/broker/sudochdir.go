package broker

// Where a brokered sudo starts. The executor forks as its own uid, and a fork
// with a working directory has to enter it as that uid before the exec. A tree
// that was never enrolled is one the executor cannot enter, so a sudo started
// there would fail before any question was asked, though root needs nothing of
// the executor's to enter it. A sudo that will run a command as root is started
// in / instead and told where to go with -D, which sudo applies as root after
// the approval; the grant's CWD=* is what lets the executor pass -D. A login
// shell (-i) is started in / as it is: sudo changes to the target's home
// whatever directory it started in.

import (
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// sudoStartRoot is where a rewritten sudo starts: a directory every uid can
// enter.
const sudoStartRoot = "/"

// sudoOption is what one of sudo's options means for the rewrite. The zero
// value is an option this does not know, which leaves the argv alone.
type sudoOption int

const (
	// optFlag takes no argument.
	optFlag sudoOption = iota + 1
	// optValue takes an argument: joined, or the next word.
	optValue
	// optLogin is -i: sudo changes to the target's home, so the directory it
	// starts in is not the one the command runs in.
	optLogin
	// optKeep leaves the argv and directory as the caller sent them: a
	// directory already chosen (-D), the caller's directory used as it is (-s),
	// a root that moves (-R), or a mode that runs no command or that sudo-rs
	// refuses -D with (-e, -l, -v, -K, -V, -h).
	optKeep
)

// sudoShort is sudo's short options, by letter.
var sudoShort = map[byte]sudoOption{
	'A': optFlag, 'b': optFlag, 'B': optFlag, 'E': optFlag, 'H': optFlag,
	'k': optFlag, 'n': optFlag, 'N': optFlag, 'P': optFlag, 'S': optFlag,
	'C': optValue, 'g': optValue, 'p': optValue, 'r': optValue, 't': optValue,
	'T': optValue, 'u': optValue, 'U': optValue,
	'i': optLogin,
	'D': optKeep, 's': optKeep, 'R': optKeep, 'e': optKeep, 'l': optKeep,
	'v': optKeep, 'K': optKeep, 'V': optKeep, 'h': optKeep,
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
	"login": optLogin,
	"chdir": optKeep, "chroot": optKeep, "edit": optKeep, "help": optKeep,
	"host": optKeep, "list": optKeep, "remove-timestamp": optKeep,
	"shell": optKeep, "validate": optKeep, "version": optKeep,
}

// sudoPrefix is what sudo's option prefix says, as far as the rewrite needs.
type sudoPrefix struct {
	// parsed is false where an option rules the rewrite out or could not be
	// read.
	parsed bool
	// command is whether a word follows the options.
	command bool
	// login is -i or --login.
	login       bool
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
			if kind == optLogin && !joined {
				p.login = true
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
			if kind == optLogin {
				p.login = true
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
	p.parsed = true
	p.command = i < len(argv)
	return p
}

// sudoStart is how a brokered sudo is started.
type sudoStart int

const (
	// sudoAsSent runs the argv as sent, in the caller's directory.
	sudoAsSent sudoStart = iota
	// sudoWithChdir runs it in / with `-D cwd` after argv[0].
	sudoWithChdir
	// sudoLogin runs it as sent, in /: a login shell changes to the target's
	// home whatever directory it starts in.
	sudoLogin
)

// planSudo is how argv, a sudo, is started. argv[0] is not read: whether the
// program is the host's sudo is the caller's question.
//
// -D is added only for a command run as root: it makes sudo enter the
// directory as the target account, which can be refused where inheriting it
// works, and -g without -u runs the command as the invoking account. A login
// shell enters the target's home as that account however it starts, so it is
// started in / for any account.
func planSudo(argv []string) sudoStart {
	p := parseSudoPrefix(argv)
	switch {
	case !p.parsed:
		return sudoAsSent
	case p.login:
		return sudoLogin
	case !p.command:
		return sudoAsSent
	case p.user != "" && p.user != "root" && p.user != "#0":
		return sudoAsSent
	case p.user == "" && p.group != "":
		return sudoAsSent
	}
	return sudoWithChdir
}

// isHostSudo reports whether a resolved program is the sudo a bare `sudo`
// resolves to on [command.env] PATH, the PATH the child gets. Resolved the same
// way, so a symlink such as an alternatives link compares by its target, and a
// file named sudo elsewhere is not taken for it.
func isHostSudo(execCfg config.CommandConfig, argv0Path string) bool {
	sudo, err := resolveProgram("sudo", sudoStartRoot, execCfg)
	return err == nil && sudo == argv0Path
}

// execTarget is the argv and directory the executor is given, and the
// directory passed to -D, "" where none was added. A sudo is rewritten only on
// a run with a run id: without one it cannot be approved, and the executor's
// own refusal to enter the cwd is the more useful failure.
func execTarget(execCfg config.CommandConfig, runID, argv0Path, cwd string,
	cmd []string) (argv []string, dir, chdir string) {
	argv = append([]string{argv0Path}, cmd[1:]...)
	if runID == "" || !isHostSudo(execCfg, argv0Path) {
		return argv, cwd, ""
	}
	switch planSudo(argv) {
	case sudoWithChdir:
		out := make([]string, 0, len(argv)+2)
		out = append(out, argv[0], "-D", cwd)
		return append(out, argv[1:]...), sudoStartRoot, cwd
	case sudoLogin:
		return argv, sudoStartRoot, ""
	case sudoAsSent:
	}
	return argv, cwd, ""
}
