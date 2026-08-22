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
// makes root a requirement here.

// asUser runs a command as another account and reports its output. An empty
// account is refused rather than passed on: `runuser -u -- cmd` takes the "--"
// as the account name and fails, which every caller here would report as a
// boundary that does not hold.
func asUser(account string, args ...string) (string, error) {
	if account == "" {
		return "", errors.New("no account named, so there is nobody to ask")
	}
	run := &runner{}
	return run.command("runuser", append([]string{"-u", account, "--"}, args...)...)
}

// asOperator runs a command as the account the broker's socket admits, root not
// being in that group. Directly when this already is them, runuser needing
// root.
func asOperator(opts DoctorOptions, args ...string) (string, error) {
	if os.Geteuid() != 0 || opts.AgentUser == "" {
		run := &runner{}
		return run.command(args[0], args[1:]...)
	}
	return asUser(opts.AgentUser, args...)
}

// canRead and canWrite answer access(2) as that account. Connecting to a unix
// socket needs write, so a socket left 0620 passes a read check.
//
// Through faramir's own binary rather than the host's `test`: access(2) answers
// for the calling process, and some `test` implementations (uutils) ignore
// supplementary group membership, which makes every group-based finding wrong
// in both directions. See cmd/faramir/access.go.
func canRead(account, path string) bool {
	_, err := asUser(account, selfPath(), "access", "--read", path)
	return err == nil
}

func canWrite(account, path string) bool {
	_, err := asUser(account, selfPath(), "access", "--write", path)
	return err == nil
}

// selfPath is the binary to re-run as another account: this process's own, so a
// doctor run from a build that is not the installed one asks itself. The
// target account has to be able to execute it, which a build in an operator's
// home may not be; DefaultBinDir is the fallback.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return filepath.Join(DefaultBinDir, "faramir")
	}
	return exe
}

// ownsMissing is what owns and ownsWithGroup report for a path that is not
// there, and what a test compares against.
const ownsMissing = "missing"

// owns reports a file's mode and owner as "%04o account", or "missing". The
// owner alone: the age key is 0400 and the audit log 0600, so no group bit is
// set and which group owns them decides nothing.
func owns(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ownsMissing
	}
	return fmt.Sprintf("%04o %s", info.Mode().Perm(), ownerName(info))
}

// ownsWithGroup is owns plus the group, for the callers that compare both:
// a message naming only the owner would carry a remedy that cannot clear the
// condition it printed.
func ownsWithGroup(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ownsMissing
	}
	return fmt.Sprintf("%04o %s:%s", info.Mode().Perm(), ownerName(info), groupName(info))
}

// diagnoseBoundaries runs every check that needs a uid other than this one.
// Held as a list so a run that skips them can say how many went unasked.
func diagnoseBoundaries(report *DoctorReport, opts DoctorOptions, cfg *config.Config, serves brokerServes) {
	// Split by what an unnamed operator costs, not by subject: canRead and
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
		report.unaskedf("boundaries", len(checks), "run doctor as root to check these: %d checks "+
			"ask what %s, %s, %s and %s can reach, and no account can answer that for "+
			"another", len(checks), opts.AgentUser, opts.BrokerUser, opts.KeeperUser,
			opts.ExecUser)
		return
	}
	// The probe itself: every check below reads a refusal as a boundary, so a
	// runuser that cannot run would report all of them as holding. Every account
	// can read /, so a refusal here is runuser failing.
	if !canRead(opts.KeeperUser, "/") {
		report.unaskedf("boundaries", len(checks), "cannot ask %s what it can reach, so none "+
			"of these %d checks were made: runuser has to be installed for this",
			opts.KeeperUser, len(checks))
		return
	}
	for _, check := range aboutTheHost {
		check()
	}
	// With no SUDO_USER and no --agent-user there is no account to put these to.
	// Named as unasked rather than run: each would otherwise report its boundary
	// as holding on the strength of a question nobody could ask.
	if opts.AgentUser == "" {
		report.unaskedf("boundaries", len(aboutTheOperator), "the agent account is not named, so "+
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
// whether any was dropped. A check that dropped one must not go on to claim
// its boundary holds: canRead answers false for an account it cannot name,
// which is what it answers for one that is properly shut out.
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

// diagnoseStore checks who can reach the ciphertext. Every account but the
// keeper must be out of the secrets group: the operator because that is the
// split, the executor because it runs whatever an agent asks for, the broker
// because read here would only add files no [secret] list names.
func diagnoseStore(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if !holds(opts.KeeperUser, opts.SecretsGroup) {
		report.addf("secrets", StatusFailed, "%s is not in %s, so it can neither decrypt "+
			"the secrets directory nor tell when it changed", opts.KeeperUser, opts.SecretsGroup)
		return
	}
	for _, account := range []string{opts.AgentUser, opts.ExecUser, opts.BrokerUser} {
		if holds(account, opts.SecretsGroup) {
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
		report.addf("secrets", StatusFailed, "%s is %04o: every account on this host can "+
			"reach the ciphertext", dir, info.Mode().Perm())
		return
	}
	if canRead(opts.AgentUser, dir) {
		report.addf("secrets", StatusFailed, "%s can list %s; the split between asking for "+
			"a value and reading the file it comes from is not in effect",
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
func diagnoseConfigWritable(report *DoctorReport, opts DoctorOptions) {
	for _, path := range []string{
		filepath.Join(opts.ConfigDir, "config.toml"),
	} {
		if !exists(path) {
			continue
		}
		if canWrite(opts.AgentUser, path) {
			report.addf("config ownership", StatusFailed, "%s can write %s, which is "+
				"where [command.env] PATH comes from: an edit there chooses what the "+
				"executor runs", opts.AgentUser, path)
			return
		}
	}
	// The creation rule is kept if it already exists, so an operator-created one
	// never went through the install's own writeFile. Whoever can write it
	// chooses which age keys future values are readable by.
	sopsConfig := filepath.Join(opts.ConfigDir, ".sops.yaml")
	if exists(sopsConfig) && canWrite(opts.AgentUser, sopsConfig) {
		report.addf("config ownership", StatusFailed, "%s can write %s, which names the "+
			"age recipients: an edit there chooses who can decrypt every value written "+
			"after it", opts.AgentUser, sopsConfig)
		return
	}
	report.addf("config ownership", StatusOK, "%s cannot write the config, its drop-ins "+
		"or the creation rule", opts.AgentUser)
}

// diagnoseInstalledFiles checks what the deny list protects. The binary is the
// hook as well as the CLI, and the two files beside it are what the hook reads;
// an account that can write any of them replaces the thing enforcing a rule
// rather than defeating one.
func diagnoseInstalledFiles(report *DoctorReport, opts DoctorOptions) {
	enforcers := []string{
		filepath.Join(DefaultBinDir, "faramir"),
		DefaultLibexecDir,
		filepath.Join(DefaultLibexecDir, "deny-patterns.txt"),
		filepath.Join(DefaultLibexecDir, "wrap.sh"),
		// The PAM helper is here for a different reason: nothing reads it to
		// enforce a rule, PAM execs it as root. An account that can write it
		// decides every escalation on this host.
		filepath.Join(DefaultLibexecDir, "pam-approve"),
	}
	for _, path := range enforcers {
		if !exists(path) {
			report.addf("installed files", StatusFailed, "%s is missing", path)
			return
		}
		// The directory too: write there is permission to replace what is in it.
		if canWrite(opts.AgentUser, path) {
			report.addf("installed files", StatusFailed, "%s can write %s, so it can "+
				"replace what enforces the deny list rather than having to get past it",
				opts.AgentUser, path)
			return
		}
	}
	report.addf("installed files", StatusOK, "%s cannot write the binary, the deny list "+
		"or the wrapper", opts.AgentUser)
}

// diagnoseDenyPatterns checks the shipped deny list was rendered for this
// install: a list naming a directory nothing uses refuses reads of a secrets
// directory that is not there and passes every read of the one that is.
// uncompilable is the rules the hook would skip, in the file's own order. The
// hook compiles each with the same case-insensitive prefix, so this asks the
// question the way the hook answers it rather than a near version of it.
func uncompilable(rules []string) []string {
	var out []string
	for _, rule := range rules {
		if _, err := regexp.Compile("(?i)" + rule); err != nil {
			out = append(out, rule)
		}
	}
	return out
}

func diagnoseDenyPatterns(report *DoctorReport, opts DoctorOptions) {
	reportDenyPatterns(report, opts, filepath.Join(DefaultLibexecDir, "deny-patterns.txt"))
}

// reportDenyPatterns is the check against a path already chosen, so a test can
// put a rendered file somewhere it may write.
func reportDenyPatterns(report *DoctorReport, opts DoctorOptions, path string) {
	body, err := os.ReadFile(path)
	if err != nil {
		report.addf("deny patterns", StatusFailed, "%s is missing, so the hook refuses "+
			"nothing: %v", path, err)
		return
	}
	// Interpolated quoted, so the comparison is against that form.
	if !strings.Contains(string(body), regexp.QuoteMeta(opts.ConfigDir)) {
		report.addf("deny patterns", StatusFailed, "%s does not name %s, so it was copied "+
			"from another install rather than rendered for this one", path, opts.ConfigDir)
		return
	}
	// Every declared command, which nothing else asks about. The blocked paths
	// check compares entries against the agents' own rule files, and a command
	// entry is in none of them: the guard's file is the whole of where one is
	// enforced, so a command missing from it is an entry doing nothing at all.
	//
	// The rendered rule rather than the words, which is what the file carries.
	var missing []string
	for _, entry := range configuredBlocked(opts.ConfigDir) {
		if entry.Command == "" {
			continue
		}
		if !strings.Contains(string(body), BlockedCommandRule(entry.Command)) {
			missing = append(missing, entry.Command)
		}
	}
	if len(missing) > 0 {
		report.addf("deny patterns", StatusFailed, "%s does not carry %d declared "+
			"command(s), which are refused by nothing until it does: %s. `faramir "+
			"block add` renders this file with the entry, so this is an entry "+
			"written by hand or a run that stopped early; `faramir init` renders it "+
			"again", path, len(missing), strings.Join(missing, ", "))
		return
	}
	// And the rest of it, against a re-render from this install's own layout.
	// The file is generated, so what it should hold is computable, and the
	// alternative is a check that asks only whether one path appears in it: the
	// render-on-add hole survived exactly that far.
	//
	// Rule lines alone, comments and blanks dropped, so a reflowed comment is not
	// reported as drift. A rule the host is missing refuses less than this
	// install asks for and fails; one it has spare refuses more, which is untidy
	// rather than unguarded, and warns.
	want := ruleLines(renderedDenyPatterns(opts.ConfigDir))
	if len(want) == 0 {
		report.addf("deny patterns", StatusOK, "%s names this install's directories "+
			"and every command it declares; what else it should hold could not be "+
			"rendered to compare", path)
		return
	}
	have := ruleLines(string(body))
	// Before the comparison, because a re-render compares the file to itself and
	// so agrees with a rule that no longer works. The hook skips a pattern that
	// will not compile rather than failing every command over it, which is the
	// right answer there and leaves the loss silent: what should have been three
	// rules is however many of them compiled.
	if broken := uncompilable(have); len(broken) > 0 {
		report.addf("deny patterns", StatusFailed, "%d of the %d rule(s) in %s will "+
			"not compile, and the hook skips a rule it cannot compile, so each one "+
			"refuses nothing: %s. An entry carrying a control character renders a "+
			"rule across two lines and breaks both halves; `faramir block ls "+
			"--declared` names the entries",
			len(broken), len(have), path, firstFew(broken))
		return
	}
	absent, spare := diffRuleLines(want, have)
	switch {
	case len(absent) > 0:
		report.addf("deny patterns", StatusFailed, "%s is missing %d of the %d rule(s) "+
			"this install renders, so the hook refuses less than the config asks "+
			"for: %s. `faramir init` renders it again",
			path, len(absent), len(want), firstFew(absent))
	case len(spare) > 0:
		report.addf("deny patterns", StatusWarn, "%s carries %d rule(s) this install "+
			"does not render, left by an earlier version or added by hand: %s. Extra "+
			"refusals, so untidy rather than unguarded; `faramir init` rewrites the "+
			"file whole", path, len(spare), firstFew(spare))
	default:
		report.addf("deny patterns", StatusOK, "%s is what this install renders: %d "+
			"rule(s), naming its own directories and every command it declares",
			path, len(want))
	}
}

// renderedDenyPatterns is what this install would write, or "" where it cannot
// be rendered. Empty rather than an error: the checks above have already said
// whether the file is there, and a re-render that fails is this command's
// problem rather than the host's.
func renderedDenyPatterns(configDir string) string {
	body, err := RenderDenyPatterns(ruleLayout(configDir))
	if err != nil {
		return ""
	}
	return string(body)
}

// ruleLines is the patterns in a rendered file: what the guard compiles, which
// is every line that is neither blank nor a comment.
func ruleLines(body string) []string {
	var out []string
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// diffRuleLines is what one list holds that the other does not, both ways.
func diffRuleLines(want, have []string) (absent, spare []string) {
	inHave := make(map[string]bool, len(have))
	for _, rule := range have {
		inHave[rule] = true
	}
	inWant := make(map[string]bool, len(want))
	for _, rule := range want {
		inWant[rule] = true
		if !inHave[rule] {
			absent = append(absent, rule)
		}
	}
	for _, rule := range have {
		if !inWant[rule] {
			spare = append(spare, rule)
		}
	}
	return absent, spare
}

// firstFew names a few rules and says how many were left out. A rule is a
// regular expression and some are long, so a finding that printed every one
// would be a finding nobody reads.
func firstFew(rules []string) string {
	const show = 2
	if len(rules) <= show {
		return strings.Join(rules, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(rules[:show], "; "),
		len(rules)-show)
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
		report.addf("age key", StatusFailed, "%s is %s, expected %s", path, got, want)
		return
	}
	accounts, skipped := askable(opts.AgentUser, opts.BrokerUser, opts.ExecUser)
	for _, account := range accounts {
		if canRead(account, path) {
			report.addf("age key", StatusFailed, "%s can read %s, so every file this "+
				"install has ever encrypted is readable by it", account, path)
			return
		}
	}
	if skipped {
		report.unaskedf("age key", 1, "%s, and %s cannot read it. The operator "+
			"account is not named, so whether it can was not asked",
			want, strings.Join(accounts, " or "))
		return
	}
	report.addf("age key", StatusOK, "%s, and only %s can read it", want, opts.KeeperUser)
}

// diagnoseOperatorKeys checks what enrolling a tree granted. init-project
// makes every directory from the home down to the tree traversable by the
// client group, which faramir-exec is in; traversal is execute without read, so
// only the enrolled tree is shared. A home that was itself enrolled is
// group-readable throughout, which carries the operator's SSH keys and the age
// key under ~/.config/sops.
func diagnoseOperatorKeys(report *DoctorReport, opts DoctorOptions) {
	// No name to ask about is how doctor was invoked -- a root login shell, a cron
	// job, a timer -- rather than anything wrong with the install.
	if opts.AgentUser == "" {
		report.unaskedf("agent keys", 1, "no agent account to ask about: "+
			"run under sudo so SUDO_USER carries it, or pass --agent-user")
		return
	}
	// A name that was given and does not resolve is different: every finding here
	// is about it, so a pass below would be about nobody.
	entry, err := user.Lookup(opts.AgentUser)
	if err != nil || entry.HomeDir == "" {
		report.addf("agent keys", StatusFailed, "%s does not resolve to an account "+
			"with a home (%v), and it is the name every check here is about. Pass "+
			"--agent-user", opts.AgentUser, err)
		return
	}
	home := filepath.Clean(entry.HomeDir)
	if !exists(home) {
		// An encrypted home is absent until its owner logs in, which is a state
		// this install is designed for rather than a fault.
		report.unaskedf("agent keys", 1, "%s does not exist, so what a brokered "+
			"command can read in it was not checked", home)
		return
	}
	if canRead(opts.ExecUser, home) {
		report.addf("agent keys", StatusFailed, "%s can list %s: the home was enrolled "+
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
func diagnoseAuditLog(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Audit.LogPath == "" {
		return
	}
	path := cfg.Audit.LogPath
	if !exists(path) {
		report.addf("audit log", StatusWarn, "%s does not exist yet; nothing has been "+
			"brokered on this host", path)
		return
	}
	want := "0600 " + opts.BrokerUser
	if got := owns(path); got != want {
		report.addf("audit log", StatusFailed, "%s is %s, expected %s", path, got, want)
		return
	}
	accounts, skipped := askable(opts.AgentUser, opts.ExecUser)
	for _, account := range accounts {
		if canRead(account, path) {
			report.addf("audit log", StatusFailed, "%s can read %s, so it can also "+
				"truncate what it says", account, path)
			return
		}
	}
	if skipped {
		report.unaskedf("audit log", 1, "%s, and %s cannot read it. The operator "+
			"account is not named, so whether it can was not asked",
			want, strings.Join(accounts, " or "))
		return
	}
	report.addf("audit log", StatusOK, "%s, readable by nobody else", want)
}

// diagnoseSockets asks who can open each one. The keeper's is the age key by
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
				"account is not named, so whether it is closed to that one was not asked",
				socket.path, strings.Join(accounts, " and "))
			continue
		}
		report.addf(socket.name, StatusOK, "%s is closed to %s", socket.path,
			strings.Join(accounts, " and "))
	}
	if path := cfg.Server.SocketPath; path != "" && exists(path) {
		switch {
		case opts.AgentUser == "":
			// The only claim here is about the operator, so there is nothing left to
			// check: an unnamed account cannot open a socket, and reporting that as the
			// grant being absent would fail every install examined from a root shell.
			report.unaskedf("broker socket", 1, "the agent account is not "+
				"named, so whether it can open %s was not asked", path)
		case canWrite(opts.AgentUser, path):
			report.addf("broker socket", StatusOK, "%s can open %s", opts.AgentUser, path)
		default:
			report.addf("broker socket", StatusFailed, "%s cannot open %s, so nothing "+
				"it runs is brokered. Membership of %s is what grants this",
				opts.AgentUser, path, opts.ClientGroup)
		}
	}
}

// diagnoseSocketPolicy reads what the config says the two internal sockets
// admit, the second lock after the modes diagnoseSockets checks: a config
// naming another account in allowed_user leaves the install one mode change
// away from a brokered command asking the keeper for every value. `faramir
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
			report.addf(socket.name, StatusWarn, "allowed_user is unset, so only %s's "+
				"own uid and root are admitted; name %s so the config says what it "+
				"allows", opts.BrokerUser, opts.BrokerUser)
		case socket.account != opts.BrokerUser:
			report.addf(socket.name, StatusFailed, "allowed_user names %s rather than "+
				"%s: %s", socket.account, opts.BrokerUser, socket.cost)
		default:
			report.addf(socket.name, StatusOK, "allowed_user is %s alone", opts.BrokerUser)
		}
	}
}

// diagnoseSSHKey covers what the agent is for: the executor authenticates and
// never holds the key. The private socket would hand it the whole agent
// protocol rather than the list and sign the relay forwards.
func diagnoseSSHKey(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Ssh.Key == "" {
		return
	}
	// The operator alongside the executor: the coding agent runs as that account,
	// so a key it can read reaches the model's context by any route the deny
	// patterns miss. init asserts the mode; this catches a chmod afterwards.
	operator, skipped := askable(opts.AgentUser)
	if key := cfg.Ssh.Key; exists(key) {
		if canRead(opts.ExecUser, key) {
			report.addf("ssh key", StatusFailed, "%s can read %s, so the agent gains "+
				"nothing: a brokered command can take the key itself", opts.ExecUser, key)
			return
		}
		for _, account := range operator {
			if canRead(account, key) {
				report.addf("ssh key", StatusFailed, "%s can read %s, and the coding agent "+
					"runs as that account: the key is readable by the thing the agent "+
					"was meant to keep it from", account, key)
				return
			}
		}
	}
	if private := cfg.Ssh.AgentSocket + ".private"; exists(private) &&
		canWrite(opts.ExecUser, private) {
		report.addf("ssh key", StatusFailed, "%s can open %s, which is ssh-agent's own "+
			"socket: that bypasses the relay and the whole agent protocol is reachable",
			opts.ExecUser, private)
		return
	}
	if skipped {
		report.unaskedf("ssh key", 1, "%s can use the agent and read no key held "+
			"by it. The agent account is not named, so whether it can read %s was "+
			"not asked", opts.ExecUser, cfg.Ssh.Key)
		return
	}
	// The executor alone, which is the account the probes above put the question
	// to; naming the operator would claim a boundary nothing asked about.
	report.addf("ssh key", StatusOK, "%s can use the agent and read no key held by it",
		opts.ExecUser)
}

// diagnoseSudoGrant checks the one grant that widens what a brokered command
// can do. Two claims under two names: the credential is checked on every host,
// and the arrangement that authenticates an escalation exists only where one
// was asked for and reports n/a where it was not.
func diagnoseSudoGrant(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	diagnoseSudoCredential(report, opts)
	diagnoseSudoArrangement(report, opts, cfg)
}

// sudoNoPasswd is passwordlessSudo, a variable so a test can answer for it
// without a sudoers file.
var sudoNoPasswd = passwordlessSudo

// diagnoseSudoCredential checks the two ways the executor could sudo with the
// broker out of the way: a NOPASSWD entry, which skips PAM entirely, and a
// password of its own. Neither may exist on any host, a grant or not.
//
// A claim that could not be put is a warning rather than a pass: silence would
// report an unread file as an absent credential.
func diagnoseSudoCredential(report *DoctorReport, opts DoctorOptions) {
	nopasswd, known := sudoNoPasswd(opts.ExecUser)
	switch {
	case !known:
		report.unaskedf("sudo credential", 1, "which account runs the executor is not "+
			"known here, so a NOPASSWD entry for it went unchecked. Pass --exec-user")
		return
	case nopasswd != "":
		report.addf("sudo credential", StatusFailed, "%s has a NOPASSWD sudoers entry (%s), so "+
			"a brokered command runs sudo without the broker, the question or a human "+
			"in the way. Remove it: NOPASSWD skips PAM, which is where the escalation "+
			"is asked for", opts.ExecUser, nopasswd)
		return
	}
	shadow, err := os.ReadFile(shadowFile)
	if err != nil {
		report.unaskedf("sudo credential", 1, "%s cannot be read (%v), so whether %s "+
			"holds a password it could authenticate with went unchecked. Re-run as root",
			shadowFile, err, opts.ExecUser)
		return
	}
	if shadowUsable(string(shadow), opts.ExecUser) {
		report.addf("sudo credential", StatusFailed, "%s has a usable password, so it can "+
			"authenticate without the broker being asked anything. Lock it: "+
			"usermod -L %s", opts.ExecUser, opts.ExecUser)
		return
	}
	report.addf("sudo credential", StatusOK, "%s holds no NOPASSWD entry from any source "+
		"and no password of its own, which are the two ways it could sudo with the "+
		"broker out of the way", opts.ExecUser)
}

// diagnoseSudoArrangement checks what authenticates an escalation and what it
// hands root: the PAM service the executor's sudo reads says what it should,
// nothing the executor can write decides it, the environment file the grant names
// is there and is not that account's to rewrite, and the fallback is not a free
// pass. All of it exists only on a host installed with --allow-sudo, so any other
// host reports n/a.
func diagnoseSudoArrangement(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Escalation.ExecUser == "" {
		report.addf("sudo grant", StatusNA, "no [escalation] section, so nothing here "+
			"authenticates an escalation and there is no PAM service, helper or fallback "+
			"to read. Brokered commands cannot sudo, which is the default arrangement; "+
			"`faramir init --allow-sudo` is what writes the three")
		return
	}

	// Where the stack that decides an escalation actually is, which is the one
	// thing the two implementations do not share. On a host whose sudo is the
	// original it is a service file of faramir's own, named by the grant. Under
	// sudo-rs there is no way to name one, so the same stack is the block in the
	// shared files and there is no service file at all.
	//
	// The block is also the tell for which implementation the install was made
	// for: one that found sudo-rs always writes it and one that found the original
	// never does. So the checks below catch a host whose `sudo` alternatives group
	// was switched after an install, in either direction, without reading the
	// grant -- which is 0440 and root's, and so out of reach of a doctor run that
	// is not.
	//
	// The executor is taken from the config rather than from opts, which is
	// derived from the exec unit and may not have been resolved: an empty name
	// would make the branch's own account test match anything.
	sudoRs := sudoRsProbe()
	execUser := cfg.Escalation.ExecUser
	pamFile := filepath.Join(pamDir, cfg.Escalation.PamService)
	var (
		body []byte
		err  error
	)
	if sudoRs {
		if problem := sudoPamBranchProblem(execUser, cfg.Escalation.Helper); problem != "" {
			report.addf("sudo grant", StatusFailed, "%s", problem)
			return
		}
		// The block is the stack, so it is what the stack checks below are put to.
		// The first shared file that is actually there: a distribution that does not
		// split the login case out has no sudo-i, and one that names sudo-i only is
		// not a host to report a missing sudo about.
		pamFile = cfg.Escalation.PamStack
		if pamFile == "" || !exists(pamFile) {
			pamFile = firstExistingStack()
		}
		if body, err = sudoPamBlock(pamFile); err != nil {
			report.addf("sudo grant", StatusFailed, "%s: %v. Re-run `faramir init "+
				"--allow-sudo`", pamFile, err)
			return
		}
	} else {
		if body, err = os.ReadFile(pamFile); err != nil {
			report.addf("sudo grant", StatusFailed, "%s is configured to authenticate "+
				"through %s, which cannot be read (%v): sudo falls back to %s/other for "+
				"that account. Re-run `faramir init --allow-sudo`",
				execUser, pamFile, err, pamDir)
			return
		}
	}
	if problem := pamStackProblem(string(body), cfg.Escalation.Helper); problem != "" {
		report.addf("sudo grant", StatusFailed, "%s: %s", pamFile, problem)
		return
	}
	if present, err := sudoPamBlockPresent(); !sudoRs && err == nil && present {
		report.addf("sudo grant", StatusFailed, "a faramir block is still in %s "+
			"while this host's sudo is the original, which selects %s with the "+
			"grant's own pam_service: the block is left over from an install made "+
			"when the `sudo` alternatives group pointed elsewhere, and the grant "+
			"beside it may name settings this sudo does not read. Re-run `faramir "+
			"init --allow-sudo`", strings.Join(sudoPamFiles(), " or "), pamFile)
		return
	}
	// The helper the stack execs, as root. It is named on a requisite line, so a
	// helper that is not there fails every escalation: nothing can be approved on
	// this host. Checked here as well as by the installed-files diagnosis, so that
	// this verdict is true on its own terms -- an operator reading the grant line
	// alone is told the grant works only where it does.
	if _, err := os.Stat(cfg.Escalation.Helper); err != nil {
		report.addf("sudo grant", StatusFailed, "%s execs %s, which cannot be read "+
			"(%v): that line is requisite, so no escalation can be approved on this "+
			"host. Re-run `faramir init --allow-sudo`",
			pamFile, cfg.Escalation.Helper, err)
		return
	}
	// An account that can write the helper chooses what decides every escalation.
	accounts, skipped := askable(opts.ExecUser, opts.AgentUser)
	for _, account := range accounts {
		if canWrite(account, cfg.Escalation.Helper) {
			report.addf("sudo grant", StatusFailed, "%s can write %s, which is what "+
				"decides every escalation: it would be choosing its own answer",
				account, cfg.Escalation.Helper)
			return
		}
	}
	// The environment file a brokered command's sudo hands root. An account that
	// can write it chooses that environment, and a missing one means what a
	// command was given does not survive its sudo. Beside the helper, which is the
	// one path this diagnosis is given.
	//
	// Read by a pam_env line in faramir's own service, on every host: sudoers has
	// an env_file that does the same job and sudo-rs has no such setting, so the
	// one mechanism that works on both is the one this asks about.
	sudoEnv := filepath.Join(filepath.Dir(cfg.Escalation.Helper), "sudo-env")
	names := pamFile + " reads it with pam_env"
	if !strings.Contains(string(body), "pam_env.so") {
		report.addf("sudo grant", StatusFailed, "%s has no pam_env line, so nothing "+
			"puts %s into what a brokered command's sudo hands root: FARAMIR_OPERATOR "+
			"and [command] env do not survive it. Re-run `faramir init --allow-sudo`",
			pamFile, sudoEnv)
		return
	}
	if _, err := os.Stat(sudoEnv); err != nil {
		report.addf("sudo grant", StatusFailed, "%s, and it cannot be read (%v): the "+
			"variables a command is given do not survive its sudo. Re-run "+
			"`faramir init --allow-sudo`", names, err)
		return
	}
	for _, account := range accounts {
		if canWrite(account, sudoEnv) {
			report.addf("sudo grant", StatusFailed, "%s can write %s, and %s: it would "+
				"be choosing the environment root is handed", account, sudoEnv, names)
			return
		}
	}
	// The fallback, for the case where the service file is ever removed: a
	// permissive `other` would authenticate anything reaching it.
	if other, err := os.ReadFile(filepath.Join(pamDir, "other")); err == nil {
		if permissiveAuth(string(other)) {
			report.addf("sudo grant", StatusFailed, "%s/other authenticates without "+
				"asking anything, so removing %s would not close this host's "+
				"escalation but open it. Make the fallback pam_deny",
				pamDir, pamFile)
			return
		}
	}
	if skipped {
		report.unaskedf("sudo grant", 1, "%s asks the broker, and %s cannot write "+
			"%s. The agent account is not named, so whether it can was not asked",
			pamFile, strings.Join(accounts, " or "), cfg.Escalation.Helper)
		return
	}
	report.addf("sudo grant", StatusOK, "%s may ask to sudo; %s asks the broker, and "+
		"root answers, one escalation per command", opts.ExecUser, pamFile)
}

// ptraceScopeFile is Yama's, and absent on a kernel built without it.
const ptraceScopeFile = "/proc/sys/kernel/yama/ptrace_scope"

// usernsSwitches are the kernel controls that decide whether an unprivileged
// account may create a user namespace, in the order they are looked for: the
// Ubuntu one is an AppArmor restriction and the Debian one a plain on/off, and
// a host has one or neither. A variable so a test can point at files it
// wrote.
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

// diagnoseUserns reports what the executor unit cannot bound.
// RestrictNamespaces= is a seccomp rule on clone()'s flags, and clone3() carries
// the same flags behind a pointer seccomp cannot read, so setting it at any
// value denies clone3() with ENOSYS; every brokered command is spawned with
// CLONE_INTO_CGROUP, which only clone3() has.
//
// So a brokered command can unshare a user namespace and hold a full capability
// set inside it. On the default install those capabilities have little to act
// on -- SystemCallFilter=@system-service denies the mount family, ProtectProc=
// masks procfs, and every boundary that matters is a uid the namespace maps
// only to itself. On a host installed with --allow-sudo the seccomp filter is
// gone by design and the mount family is reachable.
//
// Reported rather than enforced: this is a kernel-wide sysctl every other
// container and browser sandbox on the host depends on.
func diagnoseUserns(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Escalation.ExecUser == "" {
		report.addf("user namespaces", StatusNA, "no [escalation] section, so the executor "+
			"unit is rendered with SystemCallFilter=@system-service, which excludes "+
			"@mount: a namespace confers capabilities with nothing to act on. A host "+
			"that grants an escalation cannot carry that filter, which is what makes "+
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
			report.addf("user namespaces", StatusOK, "%s is %s, so %s cannot unshare a "+
				"user namespace to hold capabilities in", control.path, value, opts.ExecUser)
			return
		}
		report.addf("user namespaces", StatusWarn, "%s is %s, so a brokered command may "+
			"unshare a user namespace and hold a full capability set inside it. The "+
			"executor unit cannot refuse this: RestrictNamespaces= denies clone3(), "+
			"which is how every run is spawned into its cgroup. The uid boundaries "+
			"hold regardless, the namespace mapping only %s's own; what it reaches is "+
			"the mount family, and this host grants an escalation so no seccomp filter "+
			"is in the way. Close it with: sysctl -w %s=%s, and a line in /etc/sysctl.d",
			control.path, value, opts.ExecUser, control.path, control.shut)
		return
	}
	report.unaskedf("user namespaces", 1, "this kernel exposes no switch for "+
		"unprivileged user namespaces, so whether a brokered command may unshare "+
		"one was not asked. The executor unit cannot refuse it either: "+
		"RestrictNamespaces= denies clone3(), which is how every run is spawned "+
		"into its cgroup")
}

// diagnosePtraceScope checks what stands between a brokered command and the
// other processes of the executor's uid, on a host that grants an escalation.
// The executor daemon outlives every run, is in no run's cgroup, and receives
// each run's whole environment, so it can see every injected value. A process
// that can attach to a member of an approved run is inside that run as far as an
// escalation is concerned, ancestry being what attributes one.
//
// The daemons mark themselves undumpable, which refuses same-uid ptrace
// whatever this setting says; this check is about everything else of that uid.
// With ptrace_scope=0, the default on RHEL, Fedora and Arch, any process may
// attach to any other of the same uid, and the --allow-sudo executor unit
// carries no seccomp filter to refuse the syscall: a filter forces
// NoNewPrivileges= on, which makes sudo inert.
//
// A warning rather than a failure, being a host-wide sysctl other software has
// opinions about. N/a without a grant: that host's unit carries
// SystemCallFilter=@system-service, which excludes @ptrace.
func diagnosePtraceScope(report *DoctorReport, cfg *config.Config) {
	if cfg == nil || cfg.Escalation.ExecUser == "" {
		report.addf("ptrace scope", StatusNA, "no [escalation] section, so the executor unit is "+
			"rendered with SystemCallFilter=@system-service, which excludes @ptrace: the "+
			"syscall is refused whatever %s says. A host that grants an escalation cannot "+
			"carry that filter, which is what makes this setting decide something there",
			ptraceScopeFile)
		return
	}
	raw, err := os.ReadFile(ptraceScopeFile)
	if err != nil {
		report.unaskedf("ptrace scope", 1, "%s cannot be read (%v), so it is not "+
			"known whether one process running as %s can ptrace another. On a host "+
			"that grants an escalation, that is the difference between a run's "+
			"processes being separate and being one",
			ptraceScopeFile, err, cfg.Escalation.ExecUser)
		return
	}
	scope := strings.TrimSpace(string(raw))
	if scope == "0" {
		report.addf("ptrace scope", StatusWarn, "%s is 0, so any process running as %s "+
			"may ptrace any other of that uid. This host grants an escalation, and the "+
			"executor unit carries no seccomp filter to refuse it (a filter would "+
			"force NoNewPrivileges= on, which makes sudo inert). Set it to 1 or "+
			"higher: sysctl -w kernel.yama.ptrace_scope=1, and a line in "+
			"/etc/sysctl.d to keep it", ptraceScopeFile, cfg.Escalation.ExecUser)
		return
	}
	report.addf("ptrace scope", StatusOK, "%s is %s, so one process running as %s "+
		"cannot attach to another that is not its own descendant",
		ptraceScopeFile, scope, cfg.Escalation.ExecUser)
}

// diagnoseCgroupDelegation checks the reaper every run depends on: the executor
// confines a brokered command to a cgroup of its own and tears the cgroup down
// when the run ends, so a setsid child cannot outlive it. That needs Delegate=
// on the unit, which `init` renders. There is no process-group fallback, so
// without it the executor refuses every command.
func diagnoseCgroupDelegation(report *DoctorReport, _ DoctorOptions, _ *config.Config) {
	delegates, known := execUnitDelegates()
	switch {
	case !known:
		// systemd not reachable, or the unit not installed: the socket and broker
		// checks already speak to that.
		return
	case !delegates:
		report.addf("cgroup delegation", StatusFailed, "the executor unit does not set "+
			"Delegate=, so it cannot confine a run and the executor refuses to run one: "+
			"every brokered command fails until this is fixed. Reinstall with `faramir "+
			"init` on a host running cgroup v2 (kernel >= 5.14)")
	default:
		report.addf("cgroup delegation", StatusOK, "the executor unit is delegated a "+
			"cgroup subtree, so each run is confined and reaped and a setsid child "+
			"cannot outlive it")
	}
}

// execUnitDelegates reports whether the executor unit is granted its own cgroup
// subtree (Delegate=), and whether that could be determined. systemctl show
// reads the unit whether or not it is running, the executor being
// socket-activated and usually idle.
func execUnitDelegates() (delegates, known bool) {
	if !systemdRunning() {
		return false, false
	}
	run := &runner{}
	out, err := run.command("systemctl", "show", execUnit, "-p", "Delegate", "--value")
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(out) == "yes", true
}

// pamStackProblem names what is wrong with the authentication stack, or "".
// Two things decide whether it gates anything. `requisite` on the helper: with
// `sufficient` a refusal is not fatal, the stack falls through to whatever
// permits below, and every escalation is granted without asking. And
// `seteuid`: without it pam_exec runs the helper with the real uid, which under
// setuid sudo is the executor's own, and the broker answers the escalate op to
// root alone.
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
				"stack falls through to whatever permits below: every escalation would " +
				"be granted without asking. Re-run `faramir init --allow-sudo`"
		case !strings.Contains(line, "seteuid"):
			return "the helper runs without `seteuid`, so pam_exec runs it as the " +
				"executor rather than root: the broker answers the escalate op to root " +
				"alone, so every escalation on this host fails. Re-run `faramir init --allow-sudo`"
		case helper != "" && !strings.Contains(line, helper):
			return "the helper is not " + helper + ", so something other than faramir " +
				"decides these escalations"
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
	pid := mainPID(brokerUnit)
	if pid == "" {
		// Warn, not fail: the unit is socket-activated, so idle is its resting
		// state, and a broker that cannot be reached at all is already reported by
		// the socket check and the broker probe.
		report.unaskedf("protectproc", 1, "the broker is not running, so what "+
			"/proc shows of it cannot be checked")
		return
	}
	environ := filepath.Join("/proc", pid, "environ")
	if canRead(opts.AgentUser, environ) {
		report.addf("protectproc", StatusFailed, "%s can read %s; ProtectProc is not "+
			"in effect and a running command's value is readable there",
			opts.AgentUser, environ)
		return
	}
	report.addf("protectproc", StatusOK, "%s cannot read the broker's environ", opts.AgentUser)
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
// is what a brokered command actually gets. As the operator, the broker
// checking the peer's credentials and root not being in the shared group.
func diagnoseBrokered(report *DoctorReport, opts DoctorOptions, serves brokerServes) {
	// Three states where the command is not sent, each reported as unasked: a
	// broker that refuses it, one whose value set --check did not establish, and
	// one that is not running. Sent anyway, a refusal or an outage would come
	// back as a boundary that does not hold.
	switch serves {
	case servesNothing:
		report.unaskedf("brokered command", 1, "not asked: the broker has read "+
			"no managed file, so it refuses the command this would run")
		return
	case servesUnknown:
		report.unaskedf("brokered command", 1, "not asked: --check did not report, "+
			"so whether the broker would refuse the command this runs is unknown")
		return
	case servesValues:
		// The command is sent, which is the rest of this function.
	}
	if opts.BrokerVersion == "" {
		report.unaskedf("brokered command", 1, "not asked: the broker did not "+
			"answer, so the command this runs cannot be sent")
		return
	}
	faramir := filepath.Join(DefaultBinDir, "faramir")
	brokered := func(args ...string) (string, error) {
		return asUser(opts.AgentUser, append([]string{faramir, "run", "--quiet", "--"}, args...)...)
	}
	out, err := brokered("id", "-un")
	if err != nil {
		// Not a broken install: doctor is itself inside a brokered command, and
		// the check it wants to make is the one thing that cannot run there.
		if why := NestedRun(); why != "" {
			report.unaskedf("brokered command", 1, "not asked: %s", why)
			return
		}
		report.addf("brokered command", StatusFailed, "%s could not run one: %v",
			opts.AgentUser, err)
		return
	}
	if got := strings.TrimSpace(out); got != opts.ExecUser {
		report.addf("brokered command", StatusFailed, "runs as %s, expected %s: it is "+
			"holding whatever that account can reach", got, opts.ExecUser)
		return
	}
	// The key arrives through LoadCredential=, so the credential directory and
	// the environment are where a child might find it. Both go through a shell,
	// being a glob and an expansion.
	leaks := []struct{ name, script, want string }{
		{"the environment", `echo "[${SOPS_AGE_KEY:-unset}]"`, "[unset]"},
		{"a systemd credential", `cat /run/credentials/*/age_key 2>&1 | head -1`, ""},
	}
	for _, leak := range leaks {
		out, _ := brokered("bash", "-lc", leak.script)
		got := strings.TrimSpace(out)
		switch {
		case leak.want != "" && got != leak.want:
			report.addf("brokered command", StatusFailed, "the age key reaches a child "+
				"through %s", leak.name)
			return
		// Without the output: a finding that quotes it has published it.
		case leak.want == "" && got != "" && !strings.Contains(strings.ToLower(got), "no such file") &&
			!strings.Contains(strings.ToLower(got), "permission denied"):
			report.addf("brokered command", StatusFailed, "a child read something from "+
				"%s; inspect /run/credentials by hand", leak.name)
			return
		}
	}
	report.addf("brokered command", StatusOK, "runs as %s, and the age key reaches it "+
		"through neither the environment nor a credential", opts.ExecUser)
	diagnoseRedaction(report, opts)
}

// diagnoseRedaction is the end-to-end claim: a managed value injected into a
// real command comes back as its token. A failure means the plaintext is in
// that output, so what is reported is that no token appeared.
func diagnoseRedaction(report *DoctorReport, opts DoctorOptions) {
	faramir := filepath.Join(DefaultBinDir, "faramir")
	out, err := asOperator(opts, faramir, "refs")
	if err != nil {
		report.addf("redaction", StatusFailed, "could not list the refs to probe with: %v", err)
		return
	}
	ref := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	if ref == "" {
		report.unaskedf("redaction", 1, "no managed refs to probe with, so nothing "+
			"here proves redaction runs")
		return
	}
	probe, err := asOperator(opts, faramir, "run", "--quiet",
		"--env", "FARAMIR_DOCTOR_PROBE="+ref, "--", "printenv", "FARAMIR_DOCTOR_PROBE")
	if err != nil {
		report.addf("redaction", StatusFailed, "could not run the probe: %v", err)
		return
	}
	if !strings.Contains(probe, "«SECRET:") {
		report.addf("redaction", StatusFailed, "a command printing %s returned something "+
			"that is not its token, which is the value itself. Not quoted here: read it "+
			"with `faramir run --env X=%s -- printenv X`", ref, ref)
		return
	}
	report.addf("redaction", StatusOK, "an injected value comes back as its token")
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

// shadowFile is where the hashes are. A variable so a test can point at one it
// wrote.
var shadowFile = "/etc/shadow"

// shadowUsable reports whether an account has a password it could authenticate
// with. The second field is the hash: "!" locks it, "*" means none was ever
// set, and empty counts as none, pam_unix refusing an empty one unless the
// stack says nullok. The executor must have none: a password there is a second
// way in that nothing asks the broker about.
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
// question could be put at all. `sudo -l -U` needs root and asks sudo's own
// parser, which is the only thing that reads sudoers the way sudo does: an
// entry can come from any file in sudoers.d, from a group, or from LDAP.
// NOPASSWD is what this looks for because it skips PAM, which is where the
// escalation is asked for.
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
	// entries, which is the healthy default and prints the same output as an
	// account whose entries all authenticate.
	out, _ := run.command("sudo", "-l", "-U", account)
	for line := range strings.Lines(out) {
		if strings.Contains(line, "NOPASSWD") {
			return strings.TrimSpace(line), true
		}
	}
	return "", true
}
