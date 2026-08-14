package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
)

// The boundary checks: what each account can and cannot reach on a real host.
// The install steps can only check what they wrote, and a mode on a filesystem
// that ignores it, a socket regrouped afterwards, or an account added to the
// shared group by hand all leave the written answer intact.
//
// Asked as the uid the claim is about, root bypassing file modes, which is what
// makes root a requirement here.  Negative checks only, plus the few positives
// whose absence means the install does nothing.

// asUser runs a command as another account and reports its output.
//
// An empty account is refused rather than passed on: `runuser -u -- cmd` takes
// the "--" as the account name and fails with "user does not exist", which every
// caller here would report as a boundary that does not hold.  The callers that
// can reach this state are guarded in diagnoseBoundaries; this is so a new one
// cannot reintroduce it quietly.
func asUser(account string, args ...string) (string, error) {
	if account == "" {
		return "", errors.New("no account named, so there is nobody to ask")
	}
	run := &runner{}
	return run.command("runuser", append([]string{"-u", account, "--"}, args...)...)
}

// asOperator runs a command as the account the broker's socket admits, root not
// being in that group.  Directly when this already is them, runuser needing
// root.
func asOperator(opts DoctorOptions, args ...string) (string, error) {
	if os.Geteuid() != 0 || opts.AgentUser == "" {
		run := &runner{}
		return run.command(args[0], args[1:]...)
	}
	return asUser(opts.AgentUser, args...)
}

// canRead and canWrite answer access(2) as that account.  Connecting to a unix
// socket needs write, so a socket left 0620 passes a read check.
func canRead(account, path string) bool {
	_, err := asUser(account, "test", "-r", path)
	return err == nil
}

func canWrite(account, path string) bool {
	_, err := asUser(account, "test", "-w", path)
	return err == nil
}

// ownsMissing is what both report for a path that is not there, and what a test
// compares against.  One spelling, so a caller cannot check for a word the
// reporter stopped using.
const ownsMissing = "missing"

// owns reports a file's mode and owner as "%04o account", or "missing".
//
// The owner alone, because the checks that compare this string are about a mode
// and the uid it belongs to: the age key is 0400 and the audit log 0600, so no
// group bit is set and which group owns them decides nothing.  Requiring a group
// name here would fail every host whose service accounts do not have
// same-named primary groups.
func owns(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ownsMissing
	}
	return fmt.Sprintf("%04o %s", info.Mode().Perm(), ownerName(info))
}

// ownsWithGroup is owns plus the group, for the callers that check both.
//
// Split from owns rather than folded into it: a message is only useful beside a
// remedy that satisfies the check that printed it, and the SSH key check
// compares uid AND gid.  Naming the owner alone there is what produced a
// refusal reading "id_ed25519 is 0600 broker2 ... so broker2 cannot load it",
// with a chown beneath it that could never clear the condition.
func ownsWithGroup(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ownsMissing
	}
	return fmt.Sprintf("%04o %s:%s", info.Mode().Perm(), ownerName(info), groupName(info))
}

// diagnoseBoundaries runs every check that needs a uid other than this one.
//
// Held as a list so a run that skips them can say how many went unasked: the
// single warn line below stands for all of them, and a count taken from the
// list cannot drift from what is in it.
func diagnoseBoundaries(report *DoctorReport, opts DoctorOptions, cfg *config.Config, serves brokerServes) {
	// Split by what an unnamed operator costs, not by subject.  canRead and
	// canWrite answer false for an account they cannot name, which is the same
	// answer a boundary that holds gives, so a check whose verdict turns on the
	// operator would report an unearned OK.  A check that never asks about the
	// operator is unaffected and still runs: doctor without SUDO_USER -- a root
	// shell, a cron entry, a configuration manager -- has to keep reporting an age
	// key left 0644 or a socket regrouped by hand.
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
	}
	aboutTheOperator := []func(){
		func() { diagnoseOperatorKeys(report, opts) },
		func() { diagnoseStore(report, opts, cfg) },
		func() { diagnoseConfigWritable(report, opts) },
		func() { diagnoseInstalledFiles(report, opts) },
		func() { diagnoseProtectProc(report, opts) },
		func() { diagnoseBrokered(report, opts, serves) },
	}
	checks := append(append([]func(){}, aboutTheHost...), aboutTheOperator...)
	if os.Geteuid() != 0 {
		report.unasked("boundaries", len(checks), "run doctor as root to check these: %d checks "+
			"ask what %s, %s, %s and %s can reach, and no account can answer that for "+
			"another", len(checks), opts.AgentUser, opts.BrokerUser, opts.KeeperUser,
			opts.ExecUser)
		return
	}
	// The probe itself: every check below reads a refusal as a boundary, so a
	// runuser that cannot run would report all of them as holding.  Every account
	// can read /, so a refusal here is the mechanism.
	if !canRead(opts.KeeperUser, "/") {
		report.unasked("boundaries", len(checks), "cannot ask %s what it can reach, so none "+
			"of these %d checks were made: runuser has to be installed for this",
			opts.KeeperUser, len(checks))
		return
	}
	for _, check := range aboutTheHost {
		check()
	}
	// Reached without SUDO_USER, and with no --agent-user, there is no account
	// to put these to.  Named as unasked rather than run: each would otherwise
	// report the boundary it is about as holding, on the strength of a question
	// nobody could ask.
	if opts.AgentUser == "" {
		report.unasked("boundaries", len(aboutTheOperator), "the agent account is not named, so "+
			"%d checks that ask what it can reach were not made: pass "+
			"--agent-user, or run through sudo so SUDO_USER carries it. The rest "+
			"of the examination is unaffected", len(aboutTheOperator))
		return
	}
	for _, check := range aboutTheOperator {
		check()
	}
}

// askable drops the accounts a check cannot put a question to, and reports
// whether any was dropped.  In practice that is an unnamed operator.
//
// A check that dropped one must not go on to claim its boundary holds: canRead
// answers false for an account it cannot name, which is exactly what it answers
// for one that is properly shut out.
func askable(accounts ...string) (named []string, skipped bool) {
	for _, account := range accounts {
		if account == "" {
			skipped = true
			continue
		}
		named = append(named, account)
	}
	return named, skipped
}

// diagnoseStore checks who can reach the ciphertext.  Every account but the
// keeper must be out of the secrets group: the operator because that is the
// split, the executor because it runs whatever an agent asks for, the broker
// because read here would only add files no [secrets] list names.
func diagnoseStore(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if !holds(opts.KeeperUser, opts.SecretsGroup) {
		report.add("secrets", StatusFailed, "%s is not in %s, so it can neither decrypt "+
			"the secrets directory nor tell when it changed", opts.KeeperUser, opts.SecretsGroup)
		return
	}
	for _, account := range []string{opts.AgentUser, opts.ExecUser, opts.BrokerUser} {
		if holds(account, opts.SecretsGroup) {
			report.add("secrets", StatusFailed, "%s is in %s, so it can read and replace "+
				"the managed files. Drop it with: gpasswd -d %s %s",
				account, opts.SecretsGroup, account, opts.SecretsGroup)
			return
		}
	}
	// The group is half of it: world-readable secrets are reachable by accounts no
	// group names.
	dir := filepath.Join(opts.ConfigDir, "secrets")
	if cfg != nil && len(cfg.Secrets.Patterns) > 0 {
		dir = filepath.Dir(cfg.Secrets.Patterns[0])
	}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o007 != 0 {
		report.add("secrets", StatusFailed, "%s is %04o: every account on this host can "+
			"reach the ciphertext", dir, info.Mode().Perm())
		return
	}
	if canRead(opts.AgentUser, dir) {
		report.add("secrets", StatusFailed, "%s can list %s; the split between asking for "+
			"a value and reading the file it comes from is not in effect",
			opts.AgentUser, dir)
		return
	}
	report.add("secrets", StatusOK, "%s is the keeper's, and %s cannot list %s",
		opts.SecretsGroup, opts.AgentUser, dir)
}

// diagnoseConfigWritable checks the file that decides what a brokered command
// runs: [exec.base_env] PATH is in it, so writing it or dropping a file in
// config.d/ chooses the programs the executor resolves.
func diagnoseConfigWritable(report *DoctorReport, opts DoctorOptions) {
	for _, path := range []string{
		filepath.Join(opts.ConfigDir, "config.toml"),
		filepath.Join(opts.ConfigDir, "config.d"),
	} {
		if !exists(path) {
			continue
		}
		if canWrite(opts.AgentUser, path) {
			report.add("config ownership", StatusFailed, "%s can write %s, which is "+
				"where [exec.base_env] PATH comes from: an edit there chooses what the "+
				"executor runs", opts.AgentUser, path)
			return
		}
	}
	// The creation rule is kept if it already exists, so an operator-created one
	// never went through the install's own writeFile.  Whoever can write it
	// chooses which age keys every value encrypted from now on is readable by.
	sopsConfig := filepath.Join(opts.ConfigDir, ".sops.yaml")
	if exists(sopsConfig) && canWrite(opts.AgentUser, sopsConfig) {
		report.add("config ownership", StatusFailed, "%s can write %s, which names the "+
			"age recipients: an edit there chooses who can decrypt every value written "+
			"after it", opts.AgentUser, sopsConfig)
		return
	}
	report.add("config ownership", StatusOK, "%s cannot write the config, its drop-ins "+
		"or the creation rule", opts.AgentUser)
}

// diagnoseInstalledFiles checks what the deny list protects.  The binary is the
// hook as well as the CLI, and the two files beside it are what the hook reads;
// an account that can write any of them replaces the thing enforcing a rule
// rather than defeating one.
func diagnoseInstalledFiles(report *DoctorReport, opts DoctorOptions) {
	enforcers := []string{
		filepath.Join(DefaultBinDir, "faramir"),
		DefaultLibexecDir,
		filepath.Join(DefaultLibexecDir, "deny-patterns.txt"),
		filepath.Join(DefaultLibexecDir, "wrap.sh"),
		// The PAM helper is here for a different reason from the three above:
		// nothing reads it to enforce a rule, PAM execs it as root.  An account that
		// can write it decides every approval on this host.
		filepath.Join(DefaultLibexecDir, "pam-approve"),
	}
	for _, path := range enforcers {
		if !exists(path) {
			report.add("installed files", StatusFailed, "%s is missing", path)
			return
		}
		// The directory too: write there is permission to replace what is in it.
		if canWrite(opts.AgentUser, path) {
			report.add("installed files", StatusFailed, "%s can write %s, so it can "+
				"replace what enforces the deny list rather than having to get past it",
				opts.AgentUser, path)
			return
		}
	}
	report.add("installed files", StatusOK, "%s cannot write the binary, the deny list "+
		"or the wrapper", opts.AgentUser)
}

// diagnoseDenyPatterns checks the shipped deny list was rendered for this
// install: a list naming a directory nothing uses refuses reads of a secrets
// directory that is not there and passes every read of the one that is.
func diagnoseDenyPatterns(report *DoctorReport, opts DoctorOptions) {
	path := filepath.Join(DefaultLibexecDir, "deny-patterns.txt")
	body, err := os.ReadFile(path)
	if err != nil {
		report.add("deny patterns", StatusFailed, "%s is missing, so the hook refuses "+
			"nothing: %v", path, err)
		return
	}
	// Interpolated through regexQuote, so the comparison is against that form.
	if !strings.Contains(string(body), regexp.QuoteMeta(opts.ConfigDir)) {
		report.add("deny patterns", StatusFailed, "%s does not name %s, so it was copied "+
			"from another install rather than rendered for this one", path, opts.ConfigDir)
		return
	}
	report.add("deny patterns", StatusOK, "%s names this install's directories", path)
}

// holds is inGroup with the error folded in: an unknown account is in no group.
func holds(account, group string) bool {
	member, err := inGroup(account, group)
	return err == nil && member
}

// diagnoseAgeKey: the key decrypts every managed file retroactively, so an
// account that can read it needs nothing else here.
func diagnoseAgeKey(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	path := filepath.Join(opts.ConfigDir, "age.key")
	if cfg != nil && cfg.Keeper.AgeKeyFile != "" {
		path = cfg.Keeper.AgeKeyFile
	}
	want := "0400 " + opts.KeeperUser
	if got := owns(path); got != want {
		report.add("age key", StatusFailed, "%s is %s, expected %s", path, got, want)
		return
	}
	accounts, skipped := askable(opts.AgentUser, opts.BrokerUser, opts.ExecUser)
	for _, account := range accounts {
		if canRead(account, path) {
			report.add("age key", StatusFailed, "%s can read %s, so every file this "+
				"install has ever encrypted is readable by it", account, path)
			return
		}
	}
	if skipped {
		report.unasked("age key", 1, "%s, and %s cannot read it. The operator "+
			"account is not named, so whether it can was not asked",
			want, strings.Join(accounts, " or "))
		return
	}
	report.add("age key", StatusOK, "%s, and only %s can read it", want, opts.KeeperUser)
}

// diagnoseOperatorKeys checks what enrolling a tree granted.  init-project
// makes every directory from the home down to the tree traversable by the
// client group, which faramir-exec is in; traversal is execute without read, so
// only the enrolled tree is shared.  A home that was itself enrolled is
// group-readable throughout, which carries the operator's SSH keys and the age
// key under ~/.config/sops: a second copy of the same authority, which the
// check above cannot see.
func diagnoseOperatorKeys(report *DoctorReport, opts DoctorOptions) {
	// No name to ask about is how doctor was invoked: operatorName falls back to
	// SUDO_USER and then to the caller, and a root login shell, a cron job or a
	// systemd timer has neither.  Nothing about the install is wrong.
	if opts.AgentUser == "" {
		report.unasked("agent keys", 1, "no agent account to ask about: "+
			"run under sudo so SUDO_USER carries it, or pass --agent-user")
		return
	}
	// A name that was given and does not resolve is different: it is the name
	// every other finding here is about, so a pass below would be about nobody.
	entry, err := user.Lookup(opts.AgentUser)
	if err != nil || entry.HomeDir == "" {
		report.add("agent keys", StatusFailed, "%s does not resolve to an account "+
			"with a home (%v), and it is the name every check here is about. Pass "+
			"--agent-user", opts.AgentUser, err)
		return
	}
	home := filepath.Clean(entry.HomeDir)
	if !exists(home) {
		// An encrypted home is absent until its owner logs in, which is a state
		// this install is designed for rather than a fault.
		report.unasked("agent keys", 1, "%s does not exist, so what a brokered "+
			"command can read in it was not checked", home)
		return
	}
	if canRead(opts.ExecUser, home) {
		report.add("agent keys", StatusFailed, "%s can list %s: the home was enrolled "+
			"rather than a project inside it, so every credential in it is group-shared. "+
			"init-project grants traversal, not read", opts.ExecUser, home)
		return
	}
	// Named individually: traversal makes the home passable while its own mode
	// still refuses a listing.
	for _, relative := range []string{".ssh", ".config/sops", ".gnupg"} {
		path := filepath.Join(home, relative)
		if !exists(path) {
			continue
		}
		if canRead(opts.ExecUser, path) {
			report.add("agent keys", StatusFailed, "%s can read %s, so a brokered "+
				"command holds whatever is in it", opts.ExecUser, path)
			return
		}
	}
	report.add("agent keys", StatusOK, "%s can traverse %s and read nothing in it",
		opts.ExecUser, home)
}

// diagnoseAuditLog: the record is worth nothing if the accounts it records can
// edit it.
func diagnoseAuditLog(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Audit.LogPath == "" {
		return
	}
	path := cfg.Audit.LogPath
	if !exists(path) {
		report.add("audit log", StatusWarn, "%s does not exist yet; nothing has been "+
			"brokered on this host", path)
		return
	}
	want := "0600 " + opts.BrokerUser
	if got := owns(path); got != want {
		report.add("audit log", StatusFailed, "%s is %s, expected %s", path, got, want)
		return
	}
	accounts, skipped := askable(opts.AgentUser, opts.ExecUser)
	for _, account := range accounts {
		if canRead(account, path) {
			report.add("audit log", StatusFailed, "%s can read %s, so it can also "+
				"truncate what it says", account, path)
			return
		}
	}
	if skipped {
		report.unasked("audit log", 1, "%s, and %s cannot read it. The operator "+
			"account is not named, so whether it can was not asked",
			want, strings.Join(accounts, " or "))
		return
	}
	report.add("audit log", StatusOK, "%s, readable by nobody else", want)
}

// diagnoseSockets asks who can open each one.  The keeper's is the age key by
// another route and the executor's runs a command with no policy, redaction or
// audit record; the broker's is the one that has to be reachable.
func diagnoseSockets(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
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
		if socket.path == "" || !exists(socket.path) {
			continue
		}
		accounts, skipped := askable(socket.accounts...)
		reached := false
		for _, account := range accounts {
			if canWrite(account, socket.path) {
				report.add(socket.name, StatusFailed, "%s can open %s: %s",
					account, socket.path, socket.cost)
				reached = true
			}
		}
		if reached {
			continue
		}
		if skipped {
			report.unasked(socket.name, 1, "%s is closed to %s. The operator "+
				"account is not named, so whether it is closed to that one was not asked",
				socket.path, strings.Join(accounts, " and "))
			continue
		}
		report.add(socket.name, StatusOK, "%s is closed to %s", socket.path,
			strings.Join(accounts, " and "))
	}
	if path := cfg.Server.SocketPath; path != "" && exists(path) {
		switch {
		case opts.AgentUser == "":
			// The only claim here is about the operator, so there is nothing left to
			// check: an unnamed account cannot open a socket, and reporting that as the
			// grant being absent would fail every install examined from a root shell.
			report.unasked("broker socket", 1, "the agent account is not "+
				"named, so whether it can open %s was not asked", path)
		case canWrite(opts.AgentUser, path):
			report.add("broker socket", StatusOK, "%s can open %s", opts.AgentUser, path)
		default:
			report.add("broker socket", StatusFailed, "%s cannot open %s, so nothing "+
				"it runs is brokered. Membership of %s is what grants this",
				opts.AgentUser, path, opts.ClientGroup)
		}
	}
}

// diagnoseSocketPolicy reads what the config says the two internal sockets
// admit, the second lock after the modes diagnoseSockets checks: a config
// naming another account in allowed_user leaves the install one mode change
// away from a brokered command asking the keeper for every value.  `faramir
// broker --check` can only compare uids, so it cannot make this check as root.
func diagnoseSocketPolicy(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
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
			report.add(socket.name, StatusWarn, "allowed_user is unset, so only %s's "+
				"own uid and root are admitted; name %s so the config says what it "+
				"allows", opts.BrokerUser, opts.BrokerUser)
		case socket.account != opts.BrokerUser:
			report.add(socket.name, StatusFailed, "allowed_user names %s rather than "+
				"%s: %s", socket.account, opts.BrokerUser, socket.cost)
		default:
			report.add(socket.name, StatusOK, "allowed_user is %s alone", opts.BrokerUser)
		}
	}
}

// diagnoseSSHKey covers what the agent is for: the executor authenticates and
// never holds the key.  The private socket would hand it the whole agent
// protocol rather than the list and sign the relay forwards.
func diagnoseSSHKey(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Ssh.Key == "" {
		return
	}
	// The operator alongside the executor, and for the same reason: the coding
	// agent runs as that account, so a key it can read is one that reaches the
	// model's context by any route the deny patterns miss.  init asserts the mode;
	// this is what catches a chmod afterwards.
	operator, skipped := askable(opts.AgentUser)
	if key := cfg.Ssh.Key; exists(key) {
		if canRead(opts.ExecUser, key) {
			report.add("ssh key", StatusFailed, "%s can read %s, so the agent gains "+
				"nothing: a brokered command can take the key itself", opts.ExecUser, key)
			return
		}
		for _, account := range operator {
			if canRead(account, key) {
				report.add("ssh key", StatusFailed, "%s can read %s, and the coding agent "+
					"runs as that account: the key is readable by the thing the agent "+
					"was meant to keep it from", account, key)
				return
			}
		}
	}
	if private := cfg.Ssh.AgentSocket + ".private"; exists(private) &&
		canWrite(opts.ExecUser, private) {
		report.add("ssh key", StatusFailed, "%s can open %s, which is ssh-agent's own "+
			"socket: that bypasses the relay and the whole agent protocol is reachable",
			opts.ExecUser, private)
		return
	}
	if skipped {
		report.unasked("ssh key", 1, "%s can use the agent and read no key held "+
			"by it. The agent account is not named, so whether it can read %s was "+
			"not asked", opts.ExecUser, cfg.Ssh.Key)
		return
	}
	// The executor alone, which is the account the two probes above put the
	// question to.  Naming the operator here as well claimed a boundary nothing
	// had asked about, and read as a verdict on an account that may not even be
	// named.
	report.add("ssh key", StatusOK, "%s can use the agent and read no key held by it",
		opts.ExecUser)
}

// diagnoseSudoGrant checks the one grant that widens what a brokered command
// can do, on the host that has it and on the host that does not.
//
// Two claims under two names, because they hold on different hosts and one
// status covering both would mean a different thing on each.  The credential is
// checked everywhere; the arrangement that authenticates an approval exists
// only where one was asked for, and reports n/a where it was not.
func diagnoseSudoGrant(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	diagnoseSudoCredential(report, opts)
	diagnoseSudoArrangement(report, opts, cfg)
}

// sudoNoPasswd is passwordlessSudo, a variable so a test can answer for it
// without a sudoers file, as shadowFile is one so a test can supply its own.
var sudoNoPasswd = passwordlessSudo

// diagnoseSudoCredential checks the two ways the executor could sudo with the
// broker out of the way: a NOPASSWD entry, which skips PAM entirely, and a
// password of its own, which authenticates without the broker being asked
// anything.  Neither may exist on any host, a grant or not, so this is what
// stands behind "this host cannot sudo" as much as behind the arrangement
// below.
//
// A claim that could not be put is a warning rather than a pass: the accounts
// this examines are the ones the whole grant rests on, so silence here would
// report an unread file as an absent credential.
func diagnoseSudoCredential(report *DoctorReport, opts DoctorOptions) {
	nopasswd, known := sudoNoPasswd(opts.ExecUser)
	switch {
	case !known:
		report.unasked("sudo credential", 1, "which account runs the executor is not "+
			"known here, so a NOPASSWD entry for it went unchecked. Pass --exec-user")
		return
	case nopasswd != "":
		report.add("sudo credential", StatusFailed, "%s has a NOPASSWD sudoers entry (%s), so "+
			"a brokered command runs sudo without the broker, the question or a human "+
			"in the way. Remove it: NOPASSWD skips PAM, which is where the approval "+
			"is asked for", opts.ExecUser, nopasswd)
		return
	}
	shadow, err := os.ReadFile(shadowFile)
	if err != nil {
		report.unasked("sudo credential", 1, "%s cannot be read (%v), so whether %s "+
			"holds a password it could authenticate with went unchecked. Re-run as root",
			shadowFile, err, opts.ExecUser)
		return
	}
	if shadowUsable(string(shadow), opts.ExecUser) {
		report.add("sudo credential", StatusFailed, "%s has a usable password, so it can "+
			"authenticate without the broker being asked anything. Lock it: "+
			"usermod -L %s", opts.ExecUser, opts.ExecUser)
		return
	}
	report.add("sudo credential", StatusOK, "%s holds no NOPASSWD entry from any source "+
		"and no password of its own, which are the two ways it could sudo with the "+
		"broker out of the way", opts.ExecUser)
}

// diagnoseSudoArrangement checks what authenticates an approval: the PAM
// service the executor's sudo reads says what it is supposed to say, nothing
// the executor can write decides it, and the fallback the service falls back to
// is not a free pass.
//
// All three exist only on a host installed with --allow-sudo, so a host without
// one reports n/a: there is no file to read, and an ok would claim a stack that
// gates when there is no stack at all.
func diagnoseSudoArrangement(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.add("sudo grant", StatusNA, "no [sudo] section, so nothing here "+
			"authenticates an approval and there is no PAM service, helper or fallback "+
			"to read. Brokered commands cannot sudo, which is the default arrangement; "+
			"`faramir init --allow-sudo` is what writes the three")
		return
	}

	pamFile := filepath.Join(pamDir, cfg.Sudo.PamService)
	body, err := os.ReadFile(pamFile)
	if err != nil {
		report.add("sudo grant", StatusFailed, "%s is configured to authenticate "+
			"through %s, which cannot be read (%v): sudo falls back to %s/other for "+
			"that account. Re-run `faramir init --allow-sudo`",
			opts.ExecUser, pamFile, err, pamDir)
		return
	}
	if problem := pamStackProblem(string(body), cfg.Sudo.Helper); problem != "" {
		report.add("sudo grant", StatusFailed, "%s: %s", pamFile, problem)
		return
	}
	// The helper the stack execs, as root.  An account that can write it chooses
	// what decides every approval on this host.
	accounts, skipped := askable(opts.ExecUser, opts.AgentUser)
	for _, account := range accounts {
		if canWrite(account, cfg.Sudo.Helper) {
			report.add("sudo grant", StatusFailed, "%s can write %s, which is what "+
				"decides every approval: it would be choosing its own answer",
				account, cfg.Sudo.Helper)
			return
		}
	}
	// The fallback, for the case where the service file is ever removed: a
	// permissive `other` would authenticate anything reaching it.
	if other, err := os.ReadFile(filepath.Join(pamDir, "other")); err == nil {
		if permissiveAuth(string(other)) {
			report.add("sudo grant", StatusFailed, "%s/other authenticates without "+
				"asking anything, so removing %s would not close this host's "+
				"approval but open it. Make the fallback pam_deny",
				pamDir, pamFile)
			return
		}
	}
	if skipped {
		report.unasked("sudo grant", 1, "%s asks the broker, and %s cannot write "+
			"%s. The agent account is not named, so whether it can was not asked",
			pamFile, strings.Join(accounts, " or "), cfg.Sudo.Helper)
		return
	}
	report.add("sudo grant", StatusOK, "%s may ask to sudo; %s asks the broker, and "+
		"root answers, one approval per command", opts.ExecUser, pamFile)
}

// ptraceScopeFile is Yama's, and absent on a kernel built without it.
const ptraceScopeFile = "/proc/sys/kernel/yama/ptrace_scope"

// usernsSwitches are the kernel controls that decide whether an unprivileged
// account may create a user namespace, in the order they are looked for.  Two
// spellings, because the Ubuntu one is an AppArmor restriction and the Debian
// one is a plain on/off; a host has one or neither.  Variables so a test can
// point at files it wrote.
var usernsSwitches = []struct {
	path string
	// open is the value that permits it: the Ubuntu file is a restriction, so 0
	// permits, and the Debian one is a permission, so 1 does.
	open string
	// shut is what to set it to, printed in the remedy.
	shut string
}{
	{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "0", "1"},
	{"/proc/sys/kernel/unprivileged_userns_clone", "1", "0"},
}

// diagnoseUserns reports what the executor unit stopped bounding when
// RestrictNamespaces= was dropped.
//
// It had to go: systemd implements it as a seccomp rule on clone()'s flags, and
// clone3() carries the same flags behind a pointer seccomp cannot read, so
// setting it at any value denies clone3() with ENOSYS.  Every brokered command
// is spawned with CLONE_INTO_CGROUP, which only clone3() has, so the unit could
// spawn nothing at all.
//
// What it cost is that a brokered command can now unshare a user namespace and
// hold a full capability set inside it.  On the default install those
// capabilities have little to act on -- SystemCallFilter=@system-service denies
// the mount family, and ProtectProc= masks procfs so the kernel refuses a fresh
// /proc in there -- and every boundary that matters is a uid, which the
// namespace maps only to itself.  On a host installed with --allow-sudo the
// seccomp filter is gone by design, and the mount family is reachable.
//
// So this is reported rather than enforced, and only where the grant makes it
// worth acting on: init does not set a kernel-wide sysctl on an operator's
// behalf, that being a switch every other container and browser sandbox on the
// host also depends on.
func diagnoseUserns(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.add("user namespaces", StatusNA, "no [sudo] section, so the executor "+
			"unit is rendered with SystemCallFilter=@system-service, which excludes "+
			"@mount: a namespace confers capabilities with nothing to act on. A host "+
			"that grants an approval cannot carry that filter, which is what makes "+
			"this setting decide something there")
		return
	}
	for _, control := range usernsSwitches {
		raw, err := os.ReadFile(control.path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(raw))
		if value != control.open {
			report.add("user namespaces", StatusOK, "%s is %s, so %s cannot unshare a "+
				"user namespace to hold capabilities in", control.path, value, opts.ExecUser)
			return
		}
		report.add("user namespaces", StatusWarn, "%s is %s, so a brokered command may "+
			"unshare a user namespace and hold a full capability set inside it. The "+
			"executor unit cannot refuse this: RestrictNamespaces= denies clone3(), "+
			"which is how every run is spawned into its cgroup. The uid boundaries "+
			"hold regardless, the namespace mapping only %s's own; what it reaches is "+
			"the mount family, and this host grants an approval so no seccomp filter "+
			"is in the way. Close it with: sysctl -w %s=%s, and a line in /etc/sysctl.d",
			control.path, value, opts.ExecUser, control.path, control.shut)
		return
	}
	report.unasked("user namespaces", 1, "this kernel exposes no switch for "+
		"unprivileged user namespaces, so whether a brokered command may unshare "+
		"one was not asked. The executor unit cannot refuse it either: "+
		"RestrictNamespaces= denies clone3(), which is how every run is spawned "+
		"into its cgroup")
}

// diagnosePtraceScope checks what stands between a brokered command and the
// daemon it shares a uid with, on a host that grants an approval.
//
// The executor daemon runs as the account every brokered command runs as, is in
// no run's cgroup, and receives each run's whole environment, so it is the one
// process of that uid that outlives every run and can see every run's approval
// token.  A brokered command that can ptrace it has a foothold no cgroup
// teardown reaches and no serialisation counts, which is exactly the state the
// approval rests on not existing.
//
// The daemons mark themselves undumpable, which refuses same-uid ptrace whatever
// this setting says.  This check is about everything else of that uid: with
// ptrace_scope=0, the default on RHEL, Fedora and Arch, any process may
// attach to any other of the same uid, so two brokered commands that do overlap
// can reach into one another, and the --allow-sudo executor unit carries no
// seccomp filter to refuse the syscall (it cannot: a filter forces
// NoNewPrivileges= on, and that makes sudo inert).
//
// A warning rather than a failure: it is a host-wide sysctl that other software
// has opinions about, and faramir raising it under an operator would be
// reconfiguring the machine rather than reporting on it.
//
// N/a without a grant, and for a reason of the same shape: init renders that
// host's executor unit with SystemCallFilter=@system-service, which excludes
// @ptrace, so the syscall is refused whatever the sysctl says.  The setting only
// decides something on the host that cannot carry the filter.
func diagnosePtraceScope(report *DoctorReport, cfg *config.Config) {
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.add("ptrace scope", StatusNA, "no [sudo] section, so the executor unit is "+
			"rendered with SystemCallFilter=@system-service, which excludes @ptrace: the "+
			"syscall is refused whatever %s says. A host that grants an approval cannot "+
			"carry that filter, which is what makes this setting decide something there",
			ptraceScopeFile)
		return
	}
	raw, err := os.ReadFile(ptraceScopeFile)
	if err != nil {
		report.unasked("ptrace scope", 1, "%s cannot be read (%v), so it is not "+
			"known whether one process running as %s can ptrace another. On a host "+
			"that grants an approval, that is the difference between a run's "+
			"processes being separate and being one",
			ptraceScopeFile, err, cfg.Sudo.ExecUser)
		return
	}
	scope := strings.TrimSpace(string(raw))
	if scope == "0" {
		report.add("ptrace scope", StatusWarn, "%s is 0, so any process running as %s "+
			"may ptrace any other of that uid. This host grants an approval, and the "+
			"executor unit carries no seccomp filter to refuse it (a filter would "+
			"force NoNewPrivileges= on, which makes sudo inert). Set it to 1 or "+
			"higher: sysctl -w kernel.yama.ptrace_scope=1, and a line in "+
			"/etc/sysctl.d to keep it", ptraceScopeFile, cfg.Sudo.ExecUser)
		return
	}
	report.add("ptrace scope", StatusOK, "%s is %s, so one process running as %s "+
		"cannot attach to another that is not its own descendant",
		ptraceScopeFile, scope, cfg.Sudo.ExecUser)
}

// diagnoseCgroupDelegation checks the reaper every run depends on: the executor
// confines a brokered command to a cgroup of its own and tears the whole cgroup
// down when the run ends, so a setsid child cannot outlive it.  That needs
// Delegate= on the unit, which `init` renders on every install.  It is the one
// reaper, with no process-group fallback, so its absence is a broken host:
// without it the executor refuses every command rather than reap by process
// group, which a setsid child escapes.
func diagnoseCgroupDelegation(report *DoctorReport, _ DoctorOptions, _ *config.Config) {
	delegates, known := execUnitDelegates()
	switch {
	case !known:
		// systemd not reachable, or the unit not installed: the socket and broker
		// checks already speak to that, and this cannot add to it.
		return
	case !delegates:
		report.add("cgroup delegation", StatusFailed, "the executor unit does not set "+
			"Delegate=, so it cannot confine a run and the executor refuses to run one: "+
			"every brokered command fails until this is fixed. Reinstall with `faramir "+
			"init` on a host running cgroup v2 (kernel >= 5.14)")
	default:
		report.add("cgroup delegation", StatusOK, "the executor unit is delegated a "+
			"cgroup subtree, so each run is confined and reaped and a setsid child "+
			"cannot outlive it")
	}
}

// execUnitDelegates reports whether the executor unit is granted its own cgroup
// subtree (Delegate=), and whether that could be determined.  systemctl show
// reads the unit whether or not it is running, which matters because the
// executor is socket-activated and usually idle.
func execUnitDelegates() (delegates, known bool) {
	if !systemdRunning() {
		return false, false
	}
	run := &runner{}
	out, err := run.command("systemctl", "show", "faramir-exec.service", "-p", "Delegate", "--value")
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(out) == "yes", true
}

// pamStackProblem names what is wrong with the authentication stack, or "".
//
// Two things decide whether it gates anything.  `requisite` on the helper: with
// `sufficient` a REFUSAL is not fatal, the stack falls through to whatever
// permits below, and every approval is granted without asking.  And `seteuid`:
// without it pam_exec runs the helper with the real uid, which under setuid
// sudo is the executor's own, and the broker answers the ask_approval op to root
// alone, so the helper is refused and nothing on this host can sudo.
func pamStackProblem(body, helper string) string {
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "pam_exec.so") {
			continue
		}
		if !strings.HasPrefix(line, "auth") {
			continue
		}
		switch {
		case !strings.Contains(line, "requisite"):
			return "the helper is not `requisite`, so a refusal is not fatal and the " +
				"stack falls through to whatever permits below: every approval would " +
				"be granted without asking. Re-run `faramir init --allow-sudo`"
		case !strings.Contains(line, "seteuid"):
			return "the helper runs without `seteuid`, so pam_exec runs it as the " +
				"executor rather than root: the broker answers the ask_approval op to root " +
				"alone, so every approval on this host fails. Re-run `faramir init --allow-sudo`"
		case helper != "" && !strings.Contains(line, helper):
			return "the helper is not " + helper + ", so something other than faramir " +
				"decides these approvals"
		}
		return ""
	}
	return "no pam_exec auth line, so nothing asks the broker and whatever else " +
		"is in this file decides. Re-run `faramir init --allow-sudo`"
}

// permissiveAuth reports whether a stack authenticates without asking: a
// pam_permit with nothing that can refuse ahead of it.
func permissiveAuth(body string) bool {
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		if strings.Contains(line, "pam_permit.so") {
			return true
		}
		// Anything else in the auth stack (a unix check, a deny, an include) means
		// the fallback is not a free pass.
		return false
	}
	return false
}

// diagnoseProtectProc: a brokered command's value is in the executor's
// environment while it runs, and /proc is where another account would read it.
func diagnoseProtectProc(report *DoctorReport, opts DoctorOptions) {
	pid := mainPID("faramir-broker.service")
	if pid == "" {
		// Warn, not fail: the unit is socket-activated, so idle is its resting
		// state, and a broker that cannot be reached at all is already reported by
		// the socket check and the broker probe.
		report.unasked("protectproc", 1, "the broker is not running, so what "+
			"/proc shows of it cannot be checked")
		return
	}
	environ := filepath.Join("/proc", pid, "environ")
	if canRead(opts.AgentUser, environ) {
		report.add("protectproc", StatusFailed, "%s can read %s; ProtectProc is not "+
			"in effect and a running command's value is readable there",
			opts.AgentUser, environ)
		return
	}
	report.add("protectproc", StatusOK, "%s cannot read the broker's environ", opts.AgentUser)
}

// mainPID asks systemd rather than matching a process name.
func mainPID(unit string) string {
	if !systemdRunning() {
		return ""
	}
	run := &runner{}
	out, err := run.command("systemctl", "show", unit, "-p", "MainPID", "--value")
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(out)
	if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
		return ""
	}
	return pid
}

// diagnoseBrokered asks the broker to run something: the one place the answer
// is what a brokered command actually gets.  As the operator, the broker
// checking the peer's credentials and root not being in the shared group.
func diagnoseBrokered(report *DoctorReport, opts DoctorOptions, serves brokerServes) {
	// Three states where the command is not sent, each reported as unasked: a
	// broker that refuses it, one whose value set --check did not establish, and
	// one that is not running.  Sent anyway, a refusal or an outage comes back as
	// a boundary that does not hold; the secrets and sockets checks report both.
	//
	// Reached as root, so an unestablished value set is --check itself not having
	// reported rather than the broker's answer.
	switch serves {
	case servesNothing:
		report.unasked("brokered command", 1, "not asked: the broker has read "+
			"no managed file, so it refuses the command this would run")
		return
	case servesUnknown:
		report.unasked("brokered command", 1, "not asked: --check did not report, "+
			"so whether the broker would refuse the command this runs is unknown")
		return
	}
	if opts.BrokerVersion == "" {
		report.unasked("brokered command", 1, "not asked: the broker did not "+
			"answer, so the command this runs cannot be sent")
		return
	}
	faramir := filepath.Join(DefaultBinDir, "faramir")
	brokered := func(args ...string) (string, error) {
		return asUser(opts.AgentUser, append([]string{faramir, "run", "--quiet", "--"}, args...)...)
	}
	out, err := brokered("id", "-un")
	if err != nil {
		report.add("brokered command", StatusFailed, "%s could not run one: %v",
			opts.AgentUser, err)
		return
	}
	if got := strings.TrimSpace(out); got != opts.ExecUser {
		report.add("brokered command", StatusFailed, "runs as %s, expected %s: it is "+
			"holding whatever that account can reach", got, opts.ExecUser)
		return
	}
	// The key arrives through LoadCredential=, so the credential directory and the
	// environment are where a child might find it.  Both go through a shell, being
	// a glob and an expansion.
	leaks := []struct{ name, script, want string }{
		{"the environment", `echo "[${SOPS_AGE_KEY:-unset}]"`, "[unset]"},
		{"a systemd credential", `cat /run/credentials/*/age_key 2>&1 | head -1`, ""},
	}
	for _, leak := range leaks {
		out, _ := brokered("bash", "-lc", leak.script)
		got := strings.TrimSpace(out)
		switch {
		case leak.want != "" && got != leak.want:
			report.add("brokered command", StatusFailed, "the age key reaches a child "+
				"through %s", leak.name)
			return
		// Without the output: a finding that quotes it has published it.
		case leak.want == "" && got != "" && !strings.Contains(strings.ToLower(got), "no such file") &&
			!strings.Contains(strings.ToLower(got), "permission denied"):
			report.add("brokered command", StatusFailed, "a child read something from "+
				"%s; inspect /run/credentials by hand", leak.name)
			return
		}
	}
	report.add("brokered command", StatusOK, "runs as %s, and the age key reaches it "+
		"through neither the environment nor a credential", opts.ExecUser)
	diagnoseRedaction(report, opts)
}

// diagnoseRedaction is the end-to-end claim: a managed value injected into a
// real command comes back as its token.  The value is never in a finding on any
// path: a failure means the plaintext is in that output, so what is reported is
// that no token appeared.
func diagnoseRedaction(report *DoctorReport, opts DoctorOptions) {
	faramir := filepath.Join(DefaultBinDir, "faramir")
	out, err := asOperator(opts, faramir, "list-secrets")
	if err != nil {
		report.add("redaction", StatusFailed, "could not list the refs to probe with: %v", err)
		return
	}
	ref := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	if ref == "" {
		report.unasked("redaction", 1, "no managed refs to probe with, so nothing "+
			"here proves redaction runs")
		return
	}
	probe, err := asOperator(opts, faramir, "run", "--quiet",
		"--env", "FARAMIR_DOCTOR_PROBE="+ref, "--", "printenv", "FARAMIR_DOCTOR_PROBE")
	if err != nil {
		report.add("redaction", StatusFailed, "could not run the probe: %v", err)
		return
	}
	if !strings.Contains(probe, "«SECRET:") {
		report.add("redaction", StatusFailed, "a command printing %s returned something "+
			"that is not its token, which is the value itself. Not quoted here: read it "+
			"with `faramir run --env X=%s -- printenv X`", ref, ref)
		return
	}
	report.add("redaction", StatusOK, "an injected value comes back as its token")
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

// groupName is the group a file belongs to, or the numeric gid.
func groupName(info os.FileInfo) string {
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

// shadowFile is where the hashes are.  A variable so a test can point at one it
// wrote, as loginDefs is.
var shadowFile = "/etc/shadow"

// shadowUsable reports whether an account has a password it could authenticate
// with.  The second field is the hash: a "!" prefix locks it, "*" means no
// password was ever set, and empty is treated the same way, pam_unix refusing an
// empty one unless the stack says nullok.
//
// The executor must have none.  It authenticates through PAM against the
// broker's answer, so a password on that account is a second way in, and one
// nothing asks the broker about.
func shadowUsable(shadow, account string) bool {
	for line := range strings.Lines(shadow) {
		name, rest, found := strings.Cut(strings.TrimRight(line, "\n"), ":")
		if !found || name != account {
			continue
		}
		hash, _, _ := strings.Cut(rest, ":")
		return hash != "" && !strings.HasPrefix(hash, "!") && !strings.HasPrefix(hash, "*")
	}
	return false
}

// passwordlessSudo reports the executor's NOPASSWD entries, and whether the
// question could be put at all.  `sudo -l -U` needs root and asks sudo's own
// parser, which is the only thing that reads sudoers the way sudo does: an
// entry can come from any file in sudoers.d, from a group, or from LDAP.
//
// NOPASSWD is what this looks for because it skips PAM entirely, and PAM is
// where the approval is asked for.  An entry with it lets a brokered command
// sudo with the broker, the question and the human all out of the way.
func passwordlessSudo(account string) (string, bool) {
	if account == "" {
		return "", false
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		// No sudo on the host at all: nothing to grant and nothing to check.
		return "", true
	}
	run := &runner{}
	// The exit status is not read: sudo exits non-zero for an account with no
	// entries, which is the healthy default and the same output (none) as an
	// account whose entries all authenticate.
	out, _ := run.command("sudo", "-l", "-U", account)
	for line := range strings.Lines(out) {
		if strings.Contains(line, "NOPASSWD") {
			return strings.TrimSpace(line), true
		}
	}
	return "", true
}
