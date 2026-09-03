package doctor

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/runcmd"
)

// The boundary checks: what each account can and cannot reach on a real host.
// The install steps can only check what they wrote, and a mode on a filesystem
// that ignores it, a socket regrouped afterwards, or an account added to the
// shared group by hand all leave the written answer intact.
//
// Asked as the uid the claim is about, root bypassing file modes, which is what
// makes root a requirement here.

// asOperator runs a command as the account the broker's socket admits, root not
// being in that group. Directly when this already is them, runuser needing
// root.
func asOperator(opts Options, args ...string) (string, error) {
	if os.Geteuid() != 0 || opts.AgentUser == "" {
		return runcmd.Output(args[0], args[1:]...)
	}
	return asaccount.Output(opts.AgentUser, args...)
}

// diagnoseBoundaries runs every check that needs a uid other than this one.
// Held as a list so a run that skips them can say how many went unasked.
func diagnoseBoundaries(report *Report, opts Options, cfg *config.Config, serves brokerServes) {
	// Split by what an unnamed operator costs, not by subject: CanRead and
	// canWrite answer false for an account they cannot name, which is the answer
	// a boundary that holds gives, so a check turning on the operator would report
	// an unearned OK. A check that never asks about the operator still runs.
	//
	// The ones that ask about the operator alongside other accounts are in the
	// first list and skip it themselves rather than claiming it was asked.
	aboutTheHost := []func(){
		func() { diagnoseAgeKey(report, opts, cfg) },
		func() { diagnoseDenyPatterns(report, opts) },
		func() { diagnoseAuditLog(report, opts, cfg) },
		func() { diagnoseSockets(report, opts, cfg) },
		func() { diagnoseSocketPolicy(report, opts, cfg) },
		func() { diagnoseSSHKey(report, opts, cfg) },
		func() { diagnoseSudoGrant(report, opts, cfg) },
		func() { diagnosePtraceScope(report, cfg) },
		func() { diagnoseUserns(report, opts, cfg) },
		func() { diagnoseCgroupDelegation(report, opts, cfg) },
		func() { diagnoseConfigReadable(report, opts) },
	}
	aboutTheOperator := []func(){
		func() { diagnoseOperatorKeys(report, opts) },
		func() { diagnoseStore(report, opts, cfg) },
		func() { diagnoseConfigWritable(report, opts) },
		func() { diagnoseInstalledFiles(report, opts) },
		func() { diagnoseProtectProc(report) },
		func() { diagnoseBrokered(report, opts, cfg, serves) },
	}
	checks := append(append([]func(){}, aboutTheHost...), aboutTheOperator...)
	// Whether this host was granted an escalation is a config key rather than a
	// boundary: it needs no root and no account to answer, and it is the
	// commonest reason a brokered `sudo` fails. Answered on every path that
	// returns before the checks run, so the line is there whichever way this
	// gave up; the path that reaches them answers it through
	// diagnoseSudoArrangement, so no run reports it twice.
	//
	// Only this one, though ptrace scope and user namespaces reach their own n/a
	// from the same key: those say what the executor's seccomp filter excludes,
	// which is not what a reader whose escalation just failed came for, and each
	// is still counted as unasked below.
	if os.Geteuid() != 0 {
		noGrant(report, cfg)
		report.unaskedf("boundaries", len(checks), "%d checks were not made: "+
			"they ask what %s, %s, %s and %s can reach, and only root can run as those "+
			"accounts. Run doctor as root", len(checks), opts.AgentUser, opts.BrokerUser, opts.KeeperUser,
			opts.ExecUser)
		return
	}
	// The probe itself, per account: every check below reads a refusal as a
	// boundary, so an account whose runuser cannot run, or that cannot execute
	// this binary, would have every question about it answered as holding.
	// Every account can read /, so a refusal there is the asking failing, not
	// an answer. The keeper failing means runuser itself is broken and nothing
	// can be asked; any other dead account has its questions dropped by
	// askable, each check's own skipped bookkeeping saying so.
	if !asaccount.CanRead(opts.KeeperUser, "/") {
		// As above: this run has root and still cannot ask anything, so the checks
		// below never run and the one that needs no asking is answered here.
		noGrant(report, cfg)
		report.unaskedf("boundaries", len(checks), "runuser is not installed, "+
			"so %s cannot be asked what it can reach and %d checks were not made",
			opts.KeeperUser, len(checks))
		return
	}
	opts.deadProbers = map[string]bool{}
	for _, account := range []string{opts.AgentUser, opts.BrokerUser, opts.ExecUser} {
		if account != "" && !asaccount.CanRead(account, "/") {
			opts.deadProbers[account] = true
		}
	}
	if len(opts.deadProbers) > 0 {
		report.unaskedf("boundaries", len(opts.deadProbers), "%s cannot be "+
			"asked what it can reach: runuser refused the account, or it cannot execute "+
			"this binary. Its checks below are reported as not asked",
			strings.Join(slices.Sorted(maps.Keys(opts.deadProbers)), " or "))
	}
	for _, check := range aboutTheHost {
		check()
	}
	// With no SUDO_USER and nothing recorded there is no account to put these to.
	// Named as unasked rather than run: each would otherwise report its boundary
	// as holding on the strength of a question nobody could ask. An agent
	// account nothing can ask as is the same bar.
	if opts.AgentUser == "" || opts.deadProbers[opts.AgentUser] {
		report.unaskedf("boundaries", len(aboutTheOperator), "the agent account "+
			"is not named, so %d check(s) of what it can reach were not made. Run doctor "+
			"through sudo (SUDO_USER names the account), or record it with `sudo faramir init "+
			"--agent-user`", len(aboutTheOperator))
		return
	}
	for _, check := range aboutTheOperator {
		check()
	}
}

// askable drops the accounts a check cannot put a question to, and reports
// whether any was dropped. A check that dropped one must not go on to claim
// its boundary holds: CanRead answers false for an account it cannot name,
// which is what it answers for one that is properly shut out.
func (opts Options) askable(accounts ...string) (named []string, skipped bool) {
	for _, account := range accounts {
		if account == "" || opts.deadProbers[account] {
			skipped = true
			continue
		}
		named = append(named, account)
	}
	return named, skipped
}

// diagnoseStore checks who can reach the ciphertext. Every account but the
// keeper must be out of the secrets group: the operator because that is the
// split, the executor because it runs whatever an agent asks for, the broker
// because read here would only add files no [secret] list names.
func diagnoseStore(report *Report, opts Options, cfg *config.Config) {
	if !asaccount.Holds(opts.KeeperUser, opts.SecretsGroup) {
		report.addf("secrets", StatusFailed, "%s is not in %s, so it can neither decrypt "+
			"the secrets directory nor tell when it changed", opts.KeeperUser, opts.SecretsGroup)
		return
	}
	for _, account := range []string{opts.AgentUser, opts.ExecUser, opts.BrokerUser} {
		if asaccount.Holds(account, opts.SecretsGroup) {
			report.addf("secrets", StatusFailed, "%s is in %s, so it can read and replace "+
				"the managed files. Drop it with: gpasswd -d %s %s",
				account, opts.SecretsGroup, account, opts.SecretsGroup)
			return
		}
	}
	// The group is half of it: world-readable secrets are reachable by accounts
	// no group names.
	dir := filepath.Join(opts.ConfigDir, "secrets")
	if cfg != nil && len(cfg.Secret.Patterns) > 0 {
		dir = filepath.Dir(cfg.Secret.Patterns[0])
	}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o007 != 0 {
		report.addf("secrets", StatusFailed, "%s is %04o: every account on this "+
			"host can read the ciphertext", dir, info.Mode().Perm())
		return
	}
	if asaccount.CanRead(opts.AgentUser, dir) {
		report.addf("secrets", StatusFailed, "%s can list %s, so it can read "+
			"the files values come from instead of asking the broker for them",
			opts.AgentUser, dir)
		return
	}
	report.addf("secrets", StatusOK, "%s is the keeper's, and %s cannot list %s",
		opts.SecretsGroup, opts.AgentUser, dir)
}

// diagnoseConfigWritable checks the file that decides what a brokered command
// runs: [command.env] PATH is in it, so whoever can write it chooses the
// programs the executor resolves. One file: a config.d left over from an older
// install is not read, so it decides nothing.
func diagnoseConfigWritable(report *Report, opts Options) {
	configFile := filepath.Join(opts.ConfigDir, "config.toml")
	if hostfs.Exists(configFile) && asaccount.CanWrite(opts.AgentUser, configFile) {
		report.addf("config ownership", StatusFailed, "%s can write %s, which "+
			"sets [command.env] PATH, so an edit there chooses what the executor runs", opts.AgentUser, configFile)
		return
	}
	// The creation rule is kept if it already exists, so an operator-created one
	// never went through the install's own writeFile. Whoever can write it
	// chooses which age keys future values are readable by.
	sopsConfig := filepath.Join(opts.ConfigDir, ".sops.yaml")
	if hostfs.Exists(sopsConfig) && asaccount.CanWrite(opts.AgentUser, sopsConfig) {
		report.addf("config ownership", StatusFailed, "%s can write %s, which "+
			"names the age recipients, so an edit there chooses who can decrypt every "+
			"value written after it", opts.AgentUser, sopsConfig)
		return
	}
	report.addf("config ownership", StatusOK, "%s cannot write the config or the "+
		"creation rule", opts.AgentUser)
}

// diagnoseConfigReadable asks the broker's own account whether it can read the
// config, which is the question a reload turns on and the only one that decides
// whether this install can ever pick up a change. Every other check here reads
// a refusal as a boundary holding; this one reads it as the install being
// stuck, so it is the one boundary check whose failure is a fault rather than a
// leak.
//
// The daemons load the config once and keep serving what they have, so an
// install whose config went out of reach looks healthy from the outside: the
// broker answers, the refs resolve, and the next `faramir reload` is the first
// thing to say otherwise.
func diagnoseConfigReadable(report *Report, opts Options) {
	configFile := filepath.Join(opts.ConfigDir, "config.toml")
	if !hostfs.Exists(configFile) {
		report.addf("config reach", StatusNA, "%s is not there to be read", configFile)
		return
	}
	if opts.deadProbers[opts.BrokerUser] {
		report.unaskedf("config reach", 1, "cannot run as %s, so whether it can "+
			"read the config was not checked", opts.BrokerUser)
		return
	}
	if asaccount.CanRead(opts.BrokerUser, configFile) {
		report.addf("config reach", StatusOK, "%s can read %s", opts.BrokerUser, configFile)
		return
	}
	// Which directory to fix, not only which file could not be opened: the file
	// is usually world-readable and the refusal is a parent it cannot enter, so
	// a report naming the file sends an operator to chmod the wrong thing.
	if blocked := asaccount.BlockingDir(opts.BrokerUser, configFile); blocked != "" {
		report.addf("config reach", StatusFailed, "%s cannot read %s because it "+
			"cannot enter %s. The daemons keep serving what they loaded, and a reload "+
			"will fail; `faramir init` grants the traversal", opts.BrokerUser, configFile, blocked)
		return
	}
	report.addf("config reach", StatusFailed, "%s cannot read %s, so a reload "+
		"will fail and the daemons keep serving what they loaded",
		opts.BrokerUser, configFile)
}

// diagnoseInstalledFiles checks what the deny list protects. The binary is the
// hook as well as the CLI, and the two files beside it are what the hook reads;
// an account that can write any of them replaces the thing enforcing a rule
// rather than defeating one.
func diagnoseInstalledFiles(report *Report, opts Options) {
	enforcers := []string{
		filepath.Join(hostlayout.DefaultBinDir, "faramir"),
		// The directory too, its own rule below applying to the binary's home as
		// much as to libexec: write there is permission to replace the hook.
		hostlayout.DefaultBinDir,
		hostlayout.DefaultLibexecDir,
		filepath.Join(hostlayout.DefaultLibexecDir, "deny-patterns.txt"),
		filepath.Join(hostlayout.DefaultLibexecDir, "wrap.sh"),
		// The PAM helper is here for a different reason: nothing reads it to
		// enforce a rule, PAM execs it as root. An account that can write it
		// decides every escalation on this host.
		filepath.Join(hostlayout.DefaultLibexecDir, "pam-escalate"),
	}
	for _, path := range enforcers {
		if !hostfs.Exists(path) {
			report.addf("installed files", StatusFailed, "%s is missing", path)
			return
		}
		// The directory too: write there is permission to replace what is in it.
		if asaccount.CanWrite(opts.AgentUser, path) {
			report.addf("installed files", StatusFailed, "%s can write %s, so it "+
				"can replace what enforces the deny list",
				opts.AgentUser, path)
			return
		}
	}
	report.addf("installed files", StatusOK, "%s cannot write the binary, the deny list "+
		"or the wrapper", opts.AgentUser)
}

// diagnoseSockets asks who can open each one. The keeper's is the age key by
// another route and the executor's runs a command with no policy, redaction or
// audit record; the broker's is the one that has to be reachable.
func diagnoseSockets(report *Report, opts Options, cfg *config.Config) {
	if cfg == nil {
		return
	}
	closed := []struct {
		name     string
		path     string
		accounts []string
		cost     string
	}{
		{"keeper socket", cfg.Keeper.SocketPath, []string{opts.AgentUser, opts.ExecUser},
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor socket", cfg.Executor.SocketPath, []string{opts.AgentUser, opts.ExecUser},
			"a command sent there runs unredacted and unlogged"},
	}
	for _, socket := range closed {
		if socket.path == "" || !hostfs.Exists(socket.path) {
			continue
		}
		accounts, skipped := opts.askable(socket.accounts...)
		reached := false
		for _, account := range accounts {
			if asaccount.CanWrite(account, socket.path) {
				report.addf(socket.name, StatusFailed, "%s can open %s: %s",
					account, socket.path, socket.cost)
				reached = true
			}
		}
		if reached {
			continue
		}
		if skipped {
			report.unaskedf(socket.name, 1, "%s is closed to %s. The operator "+
				"account is not named, so whether it is closed to that account was not "+
				"checked",
				socket.path, strings.Join(accounts, " and "))
			continue
		}
		report.addf(socket.name, StatusOK, "%s is closed to %s", socket.path,
			strings.Join(accounts, " and "))
	}
	if path := cfg.Server.SocketPath; path != "" && hostfs.Exists(path) {
		switch {
		case opts.AgentUser == "":
			// The only claim here is about the operator, so there is nothing left to
			// check: an unnamed account cannot open a socket, and reporting that as the
			// grant being absent would fail every install examined from a root shell.
			report.unaskedf("broker socket", 1, "the agent account is not named, "+
				"so whether it can open %s was not checked", path)
		case asaccount.CanWrite(opts.AgentUser, path):
			report.addf("broker socket", StatusOK, "%s can open %s", opts.AgentUser, path)
		default:
			report.addf("broker socket", StatusFailed, "%s cannot open %s, so "+
				"nothing it runs is brokered. Membership of %s grants this",
				opts.AgentUser, path, opts.ClientGroup)
		}
	}
}

// diagnoseSocketPolicy reads what the config says the two internal sockets
// admit, the second lock after the modes diagnoseSockets checks: a config
// naming another account in allowed_user leaves the install one mode change
// away from a brokered command asking the keeper for every value. `faramir
// broker --check` can only compare uids, so it cannot make this check as root.
func diagnoseSocketPolicy(report *Report, opts Options, cfg *config.Config) {
	if cfg == nil {
		return
	}
	for _, socket := range []struct {
		name    string
		account string
		cost    string
	}{
		{"keeper socket policy", cfg.Keeper.AllowedUser,
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor socket policy", cfg.Executor.AllowedUser,
			"a command sent there runs unredacted and unlogged"},
	} {
		switch {
		case socket.account == "":
			report.addf(socket.name, StatusWarn, "allowed_user is unset, so only "+
				"%s's own uid and root are admitted. Set it to %s", opts.BrokerUser, opts.BrokerUser)
		case socket.account != opts.BrokerUser:
			report.addf(socket.name, StatusFailed, "allowed_user names %s rather than "+
				"%s: %s", socket.account, opts.BrokerUser, socket.cost)
		default:
			report.addf(socket.name, StatusOK, "allowed_user is %s alone", opts.BrokerUser)
		}
	}
}
