package doctor

import (
	"os/user"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
)

// diagnoseAgeKey: the key decrypts every managed file retroactively, so an
// account that can read it needs nothing else here.
// wrongMode says a file is not at the mode and owner the install sets, under
// the check's name. True where it reported, which ends the check.
func wrongMode(report *Report, name, path, want string) bool {
	if got := asaccount.Owns(path); got != want {
		report.addf(name, StatusFailed, "%s is %s, expected %s", path, got, want)
		return true
	}
	return false
}

func diagnoseAgeKey(report *Report, opts Options, cfg *config.Config) {
	path := filepath.Join(opts.ConfigDir, "age.key")
	if cfg != nil && cfg.Keeper.AgeKeyFile != "" {
		path = cfg.Keeper.AgeKeyFile
	}
	want := "0400 " + opts.KeeperUser
	if wrongMode(report, "age key", path, want) {
		return
	}
	accounts, skipped := opts.askable(opts.AgentUser, opts.BrokerUser, opts.ExecUser)
	for _, account := range accounts {
		if asaccount.CanRead(account, path) {
			report.addf("age key", StatusFailed, "%s can read %s, so it can read "+
				"every file this install has ever encrypted", account, path)
			return
		}
	}
	if skipped {
		report.unaskedf("age key", 1, "%s, and %s cannot read it. The operator "+
			"account is not named, so whether it can was not checked",
			want, strings.Join(accounts, " or "))
		return
	}
	report.addf("age key", StatusOK, "%s, and only %s can read it", want, opts.KeeperUser)
}

// diagnoseOperatorKeys checks what enrolling a tree granted. enrol
// makes every directory from the home down to the tree traversable by the
// client group, which faramir-exec is in; traversal is execute without read, so
// only the enrolled tree is shared. A home that was itself enrolled is
// group-readable throughout, which carries the operator's SSH keys and the age
// key under ~/.config/sops.
func diagnoseOperatorKeys(report *Report, opts Options) {
	// No name to ask about is how doctor was invoked -- a root login shell, a cron
	// job, a timer -- rather than anything wrong with the install.
	if opts.AgentUser == "" {
		report.unaskedf("agent keys", 1, "no agent account to check. Run doctor "+
			"through sudo (SUDO_USER names the account), or record it with `faramir init "+
			"--agent-user`")
		return
	}
	// A name that was given and does not resolve is different: every finding here
	// is about it, so a pass below would be about nobody.
	entry, err := user.Lookup(opts.AgentUser)
	if err != nil || entry.HomeDir == "" {
		report.addf("agent keys", StatusFailed, "%s does not resolve to an "+
			"account with a home (%v), and every check here is about that account. Record "+
			"it with `faramir init --agent-user`", opts.AgentUser, err)
		return
	}
	home := filepath.Clean(entry.HomeDir)
	if !hostfs.Exists(home) {
		// An encrypted home is absent until its owner logs in, which is a state
		// this install is designed for rather than a fault.
		report.unaskedf("agent keys", 1, "%s does not exist, so what a brokered "+
			"command can read in it was not checked", home)
		return
	}
	if asaccount.CanRead(opts.ExecUser, home) {
		report.addf("agent keys", StatusFailed, "%s can list %s: the home "+
			"itself was enrolled instead of a project inside it, so every credential in "+
			"it is shared with the group. Enrolment grants traversal, not read", opts.ExecUser, home)
		return
	}
	// Asked rather than assumed, the OK below claiming traversal: a home is
	// listable without being passable and passable without being listable, so the
	// check above answers neither way. An enrolment grants this and a home whose
	// mode or group has moved since takes it away, leaving nothing under it
	// reachable while every check that only asks about reading still passes.
	if !asaccount.CanTraverse(opts.ExecUser, home) {
		// Which directory refuses it, not only that one does: an ancestor closes the
		// home as surely as the home's own mode, and an operator sent to the wrong
		// one changes a mode that was never the problem. Asked about a path under the
		// home rather than the home, BlockingDir walking the way to a path and
		// leaving that path's own mode to whoever opens it.
		if blocked := asaccount.BlockingDir(opts.ExecUser, filepath.Join(home, "tree")); blocked != "" {
			report.addf("agent keys", StatusFailed, "%s cannot traverse %s "+
				"because it cannot enter %s, so no brokered command reaches an enrolled tree "+
				"under it. `faramir enrol` grants the group execute bit this needs",
				opts.ExecUser, home, blocked)
			return
		}
		report.addf("agent keys", StatusFailed, "%s cannot traverse %s, so no "+
			"brokered command reaches an enrolled tree under it. `faramir enrol` grants "+
			"it again", opts.ExecUser, home)
		return
	}
	// Named individually: traversal makes the home passable while its own mode
	// still refuses a listing.
	for _, relative := range []string{".ssh", ".config/sops", ".gnupg"} {
		path := filepath.Join(home, relative)
		if !hostfs.Exists(path) {
			continue
		}
		if asaccount.CanRead(opts.ExecUser, path) {
			report.addf("agent keys", StatusFailed, "%s can read %s, so a brokered "+
				"command holds whatever is in it", opts.ExecUser, path)
			return
		}
	}
	report.addf("agent keys", StatusOK, "%s can traverse %s and read nothing in it",
		opts.ExecUser, home)
}

// diagnoseAuditLog: the record is worth nothing if the accounts it records can
// edit it.
func diagnoseAuditLog(report *Report, opts Options, cfg *config.Config) {
	if cfg == nil || cfg.Audit.LogPath == "" {
		return
	}
	path := cfg.Audit.LogPath
	if !hostfs.Exists(path) {
		report.addf("audit log", StatusWarn, "%s does not exist yet; nothing has been "+
			"brokered on this host", path)
		return
	}
	want := "0600 " + opts.BrokerUser
	if wrongMode(report, "audit log", path, want) {
		return
	}
	accounts, skipped := opts.askable(opts.AgentUser, opts.ExecUser)
	for _, account := range accounts {
		if asaccount.CanRead(account, path) {
			report.addf("audit log", StatusFailed, "%s can read %s, so it can "+
				"also truncate it", account, path)
			return
		}
	}
	if skipped {
		report.unaskedf("audit log", 1, "%s, and %s cannot read it. The "+
			"operator account is not named, so whether it can was not checked",
			want, strings.Join(accounts, " or "))
		return
	}
	report.addf("audit log", StatusOK, "%s, readable by nobody else", want)
}

// diagnoseSSHKey covers what the agent is for: the executor authenticates and
// never holds the key. The private socket would hand it the whole agent
// protocol rather than the list and sign the relay forwards.
func diagnoseSSHKey(report *Report, opts Options, cfg *config.Config) {
	if cfg == nil || cfg.Ssh.Key == "" {
		return
	}
	// The operator alongside the executor: the coding agent runs as that account,
	// so a key it can read reaches the model's context by any route the deny
	// patterns miss. init asserts the mode; this catches a chmod afterwards.
	operator, skipped := opts.askable(opts.AgentUser)
	if key := cfg.Ssh.Key; hostfs.Exists(key) {
		if asaccount.CanRead(opts.ExecUser, key) {
			report.addf("ssh key", StatusFailed, "%s can read %s, so the agent gains "+
				"nothing: a brokered command can take the key itself", opts.ExecUser, key)
			return
		}
		for _, account := range operator {
			if asaccount.CanRead(account, key) {
				report.addf("ssh key", StatusFailed, "%s can read %s, and the "+
					"coding agent runs as that account, so the key is readable by the agent it "+
					"was meant to be kept from", account, key)
				return
			}
		}
	}
	if private := cfg.Ssh.AgentSocket + ".private"; hostfs.Exists(private) &&
		asaccount.CanWrite(opts.ExecUser, private) {
		report.addf("ssh key", StatusFailed, "%s can open %s, which is "+
			"ssh-agent's own socket, so it bypasses the relay and reaches the whole agent "+
			"protocol",
			opts.ExecUser, private)
		return
	}
	if skipped {
		report.unaskedf("ssh key", 1, "%s can use the agent and read no key it "+
			"holds. The agent account is not named, so whether it can read %s was not "+
			"checked", opts.ExecUser, cfg.Ssh.Key)
		return
	}
	// The executor alone, which is the account the probes above put the question
	// to; naming the operator would claim a boundary nothing asked about.
	report.addf("ssh key", StatusOK, "%s can use the agent and read no key it "+
		"holds",
		opts.ExecUser)
}
