package install

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
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
	// Bounded: a probe is a question, and one that hangs holds the whole
	// examination on the host being diagnosed. Generous, a brokered probe
	// carrying a real command inside it.
	return commandWithin(2*time.Minute, "runuser", append([]string{"-u", account, "--"}, args...)...)
}

// asOperator runs a command as the account the broker's socket admits, root not
// being in that group. Directly when this already is them, runuser needing
// root.
func asOperator(opts DoctorOptions, args ...string) (string, error) {
	if os.Geteuid() != 0 || opts.AgentUser == "" {
		return command(args[0], args[1:]...)
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

// canTraverse asks the question a directory answers with its execute bit:
// whether paths under it can be reached at all. Separate from canRead because
// the two are independent, a directory being listable without being passable
// and passable without being listable.
func canTraverse(account, path string) bool {
	_, err := asUser(account, selfPath(), "access", "--execute", path)
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
	if os.Geteuid() != 0 {
		report.unaskedf("boundaries", len(checks), "run doctor as root to check these: %d checks "+
			"ask what %s, %s, %s and %s can reach, and no account can answer that for "+
			"another", len(checks), opts.AgentUser, opts.BrokerUser, opts.KeeperUser,
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
	if !canRead(opts.KeeperUser, "/") {
		report.unaskedf("boundaries", len(checks), "cannot ask %s what it can reach, so none "+
			"of these %d checks were made: runuser has to be installed for this",
			opts.KeeperUser, len(checks))
		return
	}
	opts.deadProbers = map[string]bool{}
	for _, account := range []string{opts.AgentUser, opts.BrokerUser, opts.ExecUser} {
		if account != "" && !canRead(account, "/") {
			opts.deadProbers[account] = true
		}
	}
	if len(opts.deadProbers) > 0 {
		report.unaskedf("boundaries", len(opts.deadProbers), "cannot ask %s what "+
			"it can reach: runuser refused the account or it cannot execute this "+
			"binary, so its questions below are reported as unasked",
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
		report.unaskedf("boundaries", len(aboutTheOperator), "the agent account is not named or cannot be asked as, so %d check(s) that ask what it "+
			"can reach were not made: run through sudo so SUDO_USER carries it, or "+
			"record the account with `faramir init --agent-user`", len(aboutTheOperator))
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
func (opts DoctorOptions) askable(accounts ...string) (named []string, skipped bool) {
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
	configFile := filepath.Join(opts.ConfigDir, "config.toml")
	if exists(configFile) && canWrite(opts.AgentUser, configFile) {
		report.addf("config ownership", StatusFailed, "%s can write %s, which is "+
			"where [command.env] PATH comes from: an edit there chooses what the "+
			"executor runs", opts.AgentUser, configFile)
		return
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
func diagnoseConfigReadable(report *DoctorReport, opts DoctorOptions) {
	configFile := filepath.Join(opts.ConfigDir, "config.toml")
	if !exists(configFile) {
		report.addf("config reach", StatusNA, "%s is not there to be read", configFile)
		return
	}
	if opts.deadProbers[opts.BrokerUser] {
		report.unaskedf("config reach", 1, "%s cannot be asked as, so whether it "+
			"can read the config was not", opts.BrokerUser)
		return
	}
	if canRead(opts.BrokerUser, configFile) {
		report.addf("config reach", StatusOK, "%s can read %s", opts.BrokerUser, configFile)
		return
	}
	// Which directory to fix, not only which file could not be opened: the file
	// is usually world-readable and the refusal is a parent it cannot enter, so
	// a report naming the file sends an operator to chmod the wrong thing.
	if blocked := blockingDir(opts.BrokerUser, configFile); blocked != "" {
		report.addf("config reach", StatusFailed, "%s cannot read %s: it cannot enter %s. The daemons "+
			"go on serving what they loaded and a reload will refuse; `faramir init` "+
			"grants the traversal", opts.BrokerUser, configFile, blocked)
		return
	}
	report.addf("config reach", StatusFailed, "%s cannot read %s, so a reload will "+
		"refuse and the daemons will go on serving what they already have",
		opts.BrokerUser, configFile)
}

// blockingDir returns the first directory on the way to path that account
// cannot enter, or "" when every one of them is enterable. Answered from the
// modes rather than by asking the account: doctor is root here, so it can read
// what an unprivileged probe would only be refused by, and a refusal names no
// directory of its own.
func blockingDir(account, path string) string {
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

// diagnoseInstalledFiles checks what the deny list protects. The binary is the
// hook as well as the CLI, and the two files beside it are what the hook reads;
// an account that can write any of them replaces the thing enforcing a rule
// rather than defeating one.
func diagnoseInstalledFiles(report *DoctorReport, opts DoctorOptions) {
	enforcers := []string{
		filepath.Join(DefaultBinDir, "faramir"),
		// The directory too, its own rule below applying to the binary's home as
		// much as to libexec: write there is permission to replace the hook.
		DefaultBinDir,
		DefaultLibexecDir,
		filepath.Join(DefaultLibexecDir, "deny-patterns.txt"),
		filepath.Join(DefaultLibexecDir, "wrap.sh"),
		// The PAM helper is here for a different reason: nothing reads it to
		// enforce a rule, PAM execs it as root. An account that can write it
		// decides every escalation on this host.
		filepath.Join(DefaultLibexecDir, "pam-escalate"),
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
		report.addf("deny patterns", StatusFailed, "%s does not carry %d declared command(s), so they are refused by nothing: %s. "+
			"`faramir init` renders the file again", path, len(missing), strings.Join(missing, ", "))
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
		report.addf("deny patterns", StatusFailed, "%d of the %d rule(s) in %s will not compile, and the hook skips those, so each "+
			"refuses nothing: %s. A control character in an entry breaks the rule it renders; "+
			"`faramir block ls --declared` names them",
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
		report.addf("deny patterns", StatusWarn, "%s carries %d rule(s) this install does not render: %s. Extra refusals, so untidy "+
			"rather than unguarded; `faramir init` rewrites the file", path, len(spare), firstFew(spare))
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
// wrongMode says a file is not at the mode and owner the install sets, under
// the check's name. True where it reported, which ends the check.
func wrongMode(report *DoctorReport, name, path, want string) bool {
	if got := owns(path); got != want {
		report.addf(name, StatusFailed, "%s is %s, expected %s", path, got, want)
		return true
	}
	return false
}

func diagnoseAgeKey(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
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
		report.unaskedf("agent keys", 1, "no agent account to ask about: run under "+
			"sudo so SUDO_USER carries it, or record the account with "+
			"`faramir init --agent-user`")
		return
	}
	// A name that was given and does not resolve is different: every finding here
	// is about it, so a pass below would be about nobody.
	entry, err := user.Lookup(opts.AgentUser)
	if err != nil || entry.HomeDir == "" {
		report.addf("agent keys", StatusFailed, "%s does not resolve to an account "+
			"with a home (%v), and it is the name every check here is about. Record "+
			"it with `faramir init --agent-user`", opts.AgentUser, err)
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
	// Asked rather than assumed, the OK below claiming traversal: a home is
	// listable without being passable and passable without being listable, so the
	// check above answers neither way. An enrolment grants this and a home whose
	// mode or group has moved since takes it away, leaving nothing under it
	// reachable while every check that only asks about reading still passes.
	if !canTraverse(opts.ExecUser, home) {
		// Which directory refuses it, not only that one does: an ancestor closes the
		// home as surely as the home's own mode, and an operator sent to the wrong
		// one changes a mode that was never the problem. Asked about a path under the
		// home rather than the home, blockingDir walking the way to a path and
		// leaving that path's own mode to whoever opens it.
		if blocked := blockingDir(opts.ExecUser, filepath.Join(home, "tree")); blocked != "" {
			report.addf("agent keys", StatusFailed, "%s cannot traverse %s: it cannot "+
				"enter %s. No brokered command reaches an enrolled tree under it; "+
				"`faramir init-project` grants the group execute this needs",
				opts.ExecUser, home, blocked)
			return
		}
		report.addf("agent keys", StatusFailed, "%s cannot traverse %s, so no brokered "+
			"command reaches an enrolled tree under it. `faramir init-project` grants "+
			"it back", opts.ExecUser, home)
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
	if wrongMode(report, "audit log", path, want) {
		return
	}
	accounts, skipped := opts.askable(opts.AgentUser, opts.ExecUser)
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
		accounts, skipped := opts.askable(socket.accounts...)
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
	operator, skipped := opts.askable(opts.AgentUser)
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
	if opts.ExecUser == "" {
		report.unaskedf("sudo credential", 1, "which account runs the executor is not "+
			"known here, so a NOPASSWD entry for it went unchecked. Pass --exec-user")
		return
	}
	nopasswd, known := sudoNoPasswd(opts.ExecUser)
	switch {
	case !known:
		report.unaskedf("sudo credential", 1, "`sudo -l` could not list %s's entries, "+
			"so a NOPASSWD one went unchecked: a sudoers this sudo refuses to parse "+
			"reads the same from here as one holding no entry", opts.ExecUser)
		return
	case nopasswd != "":
		report.addf("sudo credential", StatusFailed, "%s has a NOPASSWD sudoers entry (%s), so a brokered command sudoes without the "+
			"broker or a human: NOPASSWD skips PAM, which is where the question is asked. "+
			"Remove it", opts.ExecUser, nopasswd)
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
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.addf("sudo grant", StatusNA, "no [sudo] section, so brokered commands cannot sudo. That is the default; "+
			"`faramir init --allow-sudo` writes the arrangement")
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
	// Whether the arrangement on disk was written for the other sudo. Set where
	// that is found and reported at the end, so the verdict is reached after the
	// stack it actually uses has been examined rather than instead of it.
	crossed := false
	execUser := cfg.Sudo.ExecUser
	pamFile := filepath.Join(pamDir, cfg.Sudo.PamService)
	var (
		body []byte
		err  error
	)
	if sudoRs {
		if problem := sudoPamBranchProblem(execUser, cfg.Sudo.Helper); problem != "" {
			report.addf("sudo grant", StatusFailed, "%s", problem)
			return
		}
		// The block is the stack, so it is what the stack checks below are put to.
		// The first shared file that is actually there: a distribution that does not
		// split the login case out has no sudo-i, and one that names sudo-i only is
		// not a host to report a missing sudo about.
		var problem string
		if body, pamFile, problem = readSudoStack(cfg); problem != "" {
			report.addf("sudo grant", StatusFailed, "%s", problem)
			return
		}
	} else if body, err = os.ReadFile(pamFile); err != nil {
		var problem string
		body, pamFile, crossed, problem = originalSudoOnRsStack(execUser, pamFile, err, cfg)
		if problem != "" {
			report.addf("sudo grant", StatusFailed, "%s", problem)
			return
		}
	}
	if problem := pamStackProblem(string(body), cfg.Sudo.Helper); problem != "" {
		report.addf("sudo grant", StatusFailed, "%s: %s", pamFile, problem)
		return
	}
	// A block in the shared stack beside a service file of faramir's own: both
	// arrangements are on disk, this sudo reads the service one, and the block is
	// left over. A failure rather than the crossed case above, because the grant
	// beside it names settings written for the other sudo.
	if present, err := sudoPamBlockPresent(); !sudoRs && !crossed && err == nil && present {
		report.addf("sudo grant", StatusFailed, "a faramir block is still in %s while this host's sudo is the original, which "+
			"selects %s instead: the block is left from an install made when the `sudo` "+
			"alternatives group pointed elsewhere. Re-run `faramir init --allow-sudo`", strings.Join(sudoPamFiles(), " or "), pamFile)
		return
	}
	// The helper the stack execs, as root. It is named on a requisite line, so a
	// helper that is not there fails every escalation: nothing can be approved on
	// this host. Checked here as well as by the installed-files diagnosis, so that
	// this verdict is true on its own terms -- an operator reading the grant line
	// alone is told the grant works only where it does.
	if _, err := os.Stat(cfg.Sudo.Helper); err != nil {
		report.addf("sudo grant", StatusFailed, "%s execs %s, which cannot be read "+
			"(%v): that line is requisite, so no escalation can be approved on this "+
			"host. Re-run `faramir init --allow-sudo`",
			pamFile, cfg.Sudo.Helper, err)
		return
	}
	// An account that can write the helper chooses what decides every escalation.
	accounts, skipped := opts.askable(opts.ExecUser, opts.AgentUser)
	for _, account := range accounts {
		if canWrite(account, cfg.Sudo.Helper) {
			report.addf("sudo grant", StatusFailed, "%s can write %s, which is what "+
				"decides every escalation: it would be choosing its own answer",
				account, cfg.Sudo.Helper)
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
	sudoEnv := filepath.Join(filepath.Dir(cfg.Sudo.Helper), "sudo-env")
	names := pamFile + " reads it with pam_env"
	if !strings.Contains(string(body), "pam_env.so") {
		report.addf("sudo grant", StatusFailed, "%s has no pam_env line, so %s does not reach a brokered "+
			"command's sudo: FARAMIR_OPERATOR and [command] env do not survive it. "+
			"Re-run `faramir init --allow-sudo`",
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
			pamFile, strings.Join(accounts, " or "), cfg.Sudo.Helper)
		return
	}
	if crossed {
		report.addf("sudo grant", StatusWarn, "%s may ask to sudo and %s asks the broker, so escalation works. The arrangement "+
			"was written for sudo-rs and this host's sudo is the original, which reads that "+
			"file as its default service. Re-run `faramir init --allow-sudo` for the "+
			"arrangement this sudo expects",
			opts.ExecUser, pamFile)
		return
	}
	report.addf("sudo grant", StatusOK, "%s may ask to sudo; %s asks the broker, and "+
		"root answers, one escalation per command", opts.ExecUser, pamFile)
}

// originalSudoOnRsStack answers the case where this host's sudo is the original
// and the service file the grant names is not there.
//
// A faramir block in the shared stack says the install was made under sudo-rs,
// whose arrangement writes no pam_service line at all. Without one the original
// sudo reaches its own default service, which is the file that block is in, so
// the grant is intact and what is crossed is which sudo the two halves were
// written for. Reporting it as a failure said every escalation fails on a host
// where each one succeeds, and this is the line an operator reads to decide
// whether escalation works.
//
// Returns the stack to examine, whether the arrangement is crossed, and a
// problem to fail on. A problem and a usable stack are exclusive.
func originalSudoOnRsStack(execUser, pamFile string, readErr error, cfg *config.Config) (
	body []byte, stack string, crossed bool, problem string) {
	present, blockErr := sudoPamBlockPresent()
	if blockErr != nil || !present {
		return nil, pamFile, false, fmt.Sprintf("%s is configured to authenticate "+
			"through %s, which cannot be read (%v): sudo falls back to %s/other for "+
			"that account. Re-run `faramir init --allow-sudo`",
			execUser, pamFile, readErr, pamDir)
	}
	if branch := sudoPamBranchProblem(execUser, cfg.Sudo.Helper); branch != "" {
		return nil, pamFile, false, branch
	}
	body, stack, problem = readSudoStack(cfg)
	if problem != "" {
		return nil, stack, false, problem
	}
	return body, stack, true, ""
}

// readSudoStack resolves which file carries sudo's stack and reads faramir's
// block out of it: the configured one where it is there, else the first shared
// file that is. problem is "" where the block was read, else the failure with
// its remedy.
func readSudoStack(cfg *config.Config) (body []byte, stack, problem string) {
	stack = cfg.Sudo.PamStack
	if stack == "" || !exists(stack) {
		stack = firstExistingStack()
	}
	body, err := sudoPamBlock(stack)
	if err != nil {
		return nil, stack, fmt.Sprintf("%s: %v. Re-run `faramir init "+
			"--allow-sudo`", stack, err)
	}
	return body, stack, ""
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
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.addf("user namespaces", StatusNA, "no [sudo] section, so the executor unit carries "+
			"SystemCallFilter=@system-service, which excludes @mount: a namespace confers "+
			"capabilities with nothing to act on")
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
		report.addf("user namespaces", StatusWarn, "%s is %s, so a brokered command may unshare a user namespace and hold a full "+
			"capability set inside it. The unit cannot refuse it: RestrictNamespaces= denies "+
			"clone3, which every run needs. The uid boundaries hold; what it reaches is "+
			"the mount family. Close it: sysctl -w %s=%s, and a line in /etc/sysctl.d",
			control.path, value, control.path, control.shut)
		return
	}
	report.unaskedf("user namespaces", 1, "this kernel exposes no switch for unprivileged user namespaces, so whether a "+
		"brokered command may unshare one was not asked. The unit cannot refuse it "+
		"either: RestrictNamespaces= denies clone3, which every run needs")
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
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.addf("ptrace scope", StatusNA, "no [sudo] section, so the executor unit carries "+
			"SystemCallFilter=@system-service, which excludes @ptrace: the syscall is refused "+
			"whatever %s says",
			ptraceScopeFile)
		return
	}
	raw, err := os.ReadFile(ptraceScopeFile)
	if err != nil {
		report.unaskedf("ptrace scope", 1, "%s cannot be read (%v), so whether one process running as %s can ptrace another "+
			"is unknown. On a host granting an escalation that decides whether a run's "+
			"processes are separate",
			ptraceScopeFile, err, cfg.Sudo.ExecUser)
		return
	}
	scope := strings.TrimSpace(string(raw))
	if scope == "0" {
		report.addf("ptrace scope", StatusWarn, "%s is 0, so any process running as %s may ptrace any other of that uid, and this "+
			"host grants an escalation. Set it to 1 or higher: sysctl -w "+
			"kernel.yama.ptrace_scope=1, and a line in /etc/sysctl.d", ptraceScopeFile, cfg.Sudo.ExecUser)
		return
	}
	report.addf("ptrace scope", StatusOK, "%s is %s, so one process running as %s "+
		"cannot attach to another that is not its own descendant",
		ptraceScopeFile, scope, cfg.Sudo.ExecUser)
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
		report.addf("cgroup delegation", StatusFailed, "the executor unit does not set Delegate=, so it cannot confine a run and refuses "+
			"every brokered command. Reinstall with `faramir init` on a host running cgroup v2 "+
			"(kernel >= 5.14)")
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
	out, ok := unitProperty(execUnit, "Delegate")
	return out == "yes", ok
}

// pamStackProblem names what is wrong with the authentication stack, or "".
// Two things decide whether it gates anything. `requisite` on the helper: with
// `sufficient` a refusal is not fatal, the stack falls through to whatever
// permits below, and every escalation is granted without asking. And
// `seteuid`: without it pam_exec runs the helper with the real uid, which under
// setuid sudo is the executor's own, and the broker answers the escalate op to
// root alone.
func pamStackProblem(body, helper string) string {
	// Position matters as much as the helper line itself: an auth entry ahead of
	// it authenticates before the broker is asked, and the requisite below then
	// gates nothing. Ahead of the helper only the sudo-rs block's own branch may
	// stand, a pam_succeed_if under a [success=ok ...] spec; the sudo-rs path
	// holds what is outside the block to the same rule with firstAuthLine.
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@include") {
			return "an @include ahead of the helper pulls in an auth stack that " +
				"answers before the broker is asked (" + line + "). Re-run " +
				"`faramir init --allow-sudo`"
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "auth" {
			continue
		}
		control, rest := pamAuthLine(fields)
		module := ""
		if len(rest) > 0 {
			module = rest[0]
		}
		if module != "pam_exec.so" {
			if module == "pam_succeed_if.so" && strings.HasPrefix(control, "[success=ok ") {
				continue
			}
			return "an auth line ahead of the helper answers before the broker is " +
				"asked (" + line + "). Re-run `faramir init --allow-sudo`"
		}
		// The helper line, each word matched as the field it is rather than as a
		// substring anything on the line could carry.
		switch {
		case control != "requisite":
			return "the helper is not `requisite`, so a refusal falls through to whatever permits " +
				"below and every escalation is granted without asking. Re-run `faramir init " +
				"--allow-sudo`"
		case !slices.Contains(rest, "seteuid"):
			return "the helper runs without `seteuid`, so pam_exec runs it as the executor rather " +
				"than root, and the broker answers the escalate op to root alone: every " +
				"escalation fails. Re-run `faramir init --allow-sudo`"
		case helper != "" && !slices.Contains(rest, helper):
			return "the helper is not " + helper + ", so something other than faramir " +
				"decides these escalations"
		}
		return ""
	}
	return "no pam_exec auth line, so nothing asks the broker and whatever else " +
		"is in this file decides. Re-run `faramir init --allow-sudo`"
}

// pamAuthLine splits one auth entry into its control field, a bracketed spec
// kept whole, and the module with its arguments after it.
func pamAuthLine(fields []string) (control string, rest []string) {
	if len(fields) < 2 {
		return "", nil
	}
	i := 2
	if strings.HasPrefix(fields[1], "[") {
		for i < len(fields) && !strings.HasSuffix(fields[i-1], "]") {
			i++
		}
	}
	return strings.Join(fields[1:i], " "), fields[i:]
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

// diagnoseProtectProc: all three units carry ProtectProc=invisible, which
// hides every other account's processes from the daemon; a drop-in or a hand
// edit that takes it off leaves that daemon reading a /proc it has no business
// seeing. Asked of systemd, which resolves drop-ins, rather than of the files.
//
// What this deliberately does not probe: another account reading a daemon's
// /proc/<pid>/environ. The kernel's own mode bits refuse that on every host
// whatever the unit says, so a probe there passes unconditionally and measures
// nothing; the e2e suite reads the boundary itself.
func diagnoseProtectProc(report *DoctorReport) {
	for _, unit := range []string{brokerUnit, keeperUnit, execUnit} {
		value, ok := unitProperty(unit, "ProtectProc")
		if !ok {
			report.unaskedf("protectproc", 1, "systemd could not report %s's "+
				"ProtectProc, so it was not asked", unit)
			continue
		}
		if value != "invisible" {
			report.addf("protectproc", StatusFailed, "%s runs with ProtectProc=%s "+
				"rather than the invisible the install writes, so that daemon sees "+
				"every account's /proc. A drop-in or an edit took it off; `sudo "+
				"faramir init` writes the unit back", unit, value)
			continue
		}
		report.addf("protectproc", StatusOK, "%s hides other accounts' /proc", unit)
	}
}

// diagnoseBrokered asks the broker to run something: the one place the answer
// is what a brokered command actually gets. As the operator, the broker
// checking the peer's credentials and root not being in the shared group.
func diagnoseBrokered(report *DoctorReport, opts DoctorOptions, cfg *config.Config, serves brokerServes) {
	// Three states where the command is not sent, each reported as unasked: a
	// broker that refuses it, one whose value set --check did not establish, and
	// one that is not running. Sent anyway, a refusal or an outage would come
	// back as a boundary that does not hold.
	switch serves {
	case servesNothing:
		report.unaskedf("brokered command", 1, "not asked: a managed file did not "+
			"load, so the broker refuses the command this would run")
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
	// being a glob and an expansion, and -c alone: -l would source the
	// executor's login profiles on every run and let a banner into the verdict.
	//
	// Each script answers with a word of its own, so the verdict reads the same
	// under any locale, and nothing a probe might find is printed or carried:
	// the environment probe never expands the value and the credential probe
	// sends the read to /dev/null, so a hit reaches neither this output nor the
	// audit record.
	leaks := []struct{ name, script string }{
		{"the environment", `[ -z "${SOPS_AGE_KEY:-}" ] && echo clean || echo readable`},
		{"a systemd credential", `cat /run/credentials/*/age_key >/dev/null 2>&1 && echo readable || echo clean`},
	}
	for _, leak := range leaks {
		out, err := brokered("bash", "-c", leak.script)
		got := strings.TrimSpace(out)
		switch {
		case err != nil:
			// A probe that did not run answered nothing: scoring it clean would
			// pass the boundary on a broken probe, and scoring it a leak would
			// fail a healthy host over one.
			report.unaskedf("brokered command", 1, "the %s probe could not run "+
				"(%v), so whether the age key reaches a child there was not asked",
				leak.name, err)
			return
		case got == "readable":
			report.addf("brokered command", StatusFailed, "the age key reaches a child "+
				"through %s; inspect it by hand", leak.name)
			return
		case got != "clean":
			report.unaskedf("brokered command", 1, "the %s probe answered something "+
				"other than its own verdict, so it was not read", leak.name)
			return
		}
	}
	report.addf("brokered command", StatusOK, "runs as %s, and the age key reaches it "+
		"through neither the environment nor a credential", opts.ExecUser)
	diagnoseRedaction(report, opts, cfg)
}

// diagnoseRedaction is the end-to-end claim, made with a value of its own: a
// synthetic secret is sealed into the store, refreshed in, injected into a
// real command and expected back as exactly its token, then removed and
// refreshed out. A dedicated value rather than one of the operator's, so a
// host whose redaction is broken leaks a random string into its own audit log
// and nothing else.
func diagnoseRedaction(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	const name = "redaction"
	if cfg == nil {
		report.unaskedf(name, 1, "the config did not load, so no probe value was sealed")
		return
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		report.unaskedf(name, 1, "sops is not on this PATH, so no probe value "+
			"could be sealed and redaction was not exercised")
		return
	}
	target := filepath.Join(opts.ConfigDir, "secrets", "doctor-probe.sops.yml")
	if exists(target) {
		report.unaskedf(name, 1, "%s already exists, so no probe was written over it", target)
		return
	}
	value := make([]byte, 16)
	if _, err := cryptorand.Read(value); err != nil {
		report.unaskedf(name, 1, "no randomness for a probe value: %v", err)
		return
	}
	plainDir, err := os.MkdirTemp("", "faramir-doctor")
	if err != nil {
		report.unaskedf(name, 1, "no directory for the probe's plaintext: %v", err)
		return
	}
	defer func() { _ = os.RemoveAll(plainDir) }()
	plain := filepath.Join(plainDir, "probe.yml")
	body := "doctor:\n  probe: " + hex.EncodeToString(value) + "\n"
	if err := os.WriteFile(plain, []byte(body), 0o600); err != nil {
		report.unaskedf(name, 1, "could not write the probe's plaintext: %v", err)
		return
	}
	sealed, err := commandWithin(time.Minute, sops,
		"--config", filepath.Join(opts.ConfigDir, ".sops.yaml"),
		"--encrypt", "--filename-override", target, plain)
	if err != nil {
		report.unaskedf(name, 1, "could not seal a probe value (%v), so redaction "+
			"was not exercised; `sops config` and `rule coverage` say why sealing fails", err)
		return
	}
	// 0640 into the setgid store, which hands the keeper's group over, exactly
	// as a managed file is written.
	if err := os.WriteFile(target, []byte(sealed), 0o640); err != nil { //nolint:gosec // G306: the store's own mode; the file is ciphertext and the keeper's group must read it
		report.unaskedf(name, 1, "could not write the probe into the store: %v", err)
		return
	}
	// Removed and refreshed out whatever happens below, so the probe never
	// outlives the examination.
	defer func() {
		_ = os.Remove(target)
		_ = refreshStore(cfg.Server.SocketPath)
	}()
	if why := refreshStore(cfg.Server.SocketPath); why != "" {
		report.unaskedf(name, 1, "the broker did not take the probe value: %s", why)
		return
	}
	faramir := filepath.Join(DefaultBinDir, "faramir")
	probe, err := asOperator(opts, faramir, "run", "--quiet",
		"--env", "FARAMIR_DOCTOR_PROBE=faramir://doctor/probe", "--",
		"printenv", "FARAMIR_DOCTOR_PROBE")
	if err != nil {
		report.addf(name, StatusFailed, "could not run the probe: %v", err)
		return
	}
	// The whole output has to be the probe's own token: a substring match
	// would pass a value redacted in part.
	if strings.TrimSpace(probe) != redact.TokenFor("doctor/probe") {
		report.addf(name, StatusFailed, "a command printing the sealed probe value "+
			"returned something other than its token, so injected values reach "+
			"output unredacted. The probe value is synthetic and already removed")
		return
	}
	report.addf(name, StatusOK, "a sealed probe value came back as exactly its token")
}

// refreshStore asks the running broker to re-read the managed store, the same
// op `faramir vault` sends, and returns why it did not, empty on success.
func refreshStore(socketPath string) string {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		return fmt.Sprintf("the broker could not be reached at %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	if err := sockutil.Send(conn, map[string]any{
		"op": "refresh", "version": version.Version}); err != nil {
		return fmt.Sprintf("the refresh could not be sent: %v", err)
	}
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil || len(line) == 0 {
		return "the broker did not answer the refresh"
	}
	var response struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return "the refresh answer was not readable"
	}
	if response.Error != nil {
		return response.Error.Message
	}
	return ""
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
	// The exit status is not read: sudo exits non-zero for an account with no
	// entries, which is the healthy default and prints the same output as an
	// account whose entries all authenticate. What is read is the listing
	// itself, which names the account whenever it ran.
	out, _ := commandWithin(30*time.Second, "sudo", "-l", "-U", account)
	return noPasswdEntry(out, account)
}

// noPasswdEntry reads a `sudo -l -U` listing for a grant that skips PAM. A
// listing that ran names the account whatever it grants; output that does not
// is sudo itself failing (a sudoers syntax error, an -l this sudo does not
// take), which must not read as no entry. `!authenticate` is the other
// spelling of the same grant, and never prints the string NOPASSWD.
func noPasswdEntry(out, account string) (string, bool) {
	if !strings.Contains(out, account) {
		return "", false
	}
	for line := range strings.Lines(out) {
		if strings.Contains(line, "NOPASSWD") || strings.Contains(line, "!authenticate") {
			return strings.TrimSpace(line), true
		}
	}
	return "", true
}
