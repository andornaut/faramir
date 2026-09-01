package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/runcmd"
)

// diagnoseSudoGrant checks the one grant that widens what a brokered command
// can do. Two claims under two names: the credential is checked on every host,
// and the arrangement that authenticates an escalation exists only where one
// was asked for and reports n/a where it was not.
func diagnoseSudoGrant(report *Report, opts Options, cfg *config.Config) {
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
func diagnoseSudoCredential(report *Report, opts Options) {
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
			"holds a password it could authenticate with went unchecked. The operator can re-run this as root",
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
func diagnoseSudoArrangement(report *Report, opts Options, cfg *config.Config) {
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
	sudoRs := hostsudo.RsProbe()
	// Whether the arrangement on disk was written for the other sudo. Set where
	// that is found and reported at the end, so the verdict is reached after the
	// stack it actually uses has been examined rather than instead of it.
	crossed := false
	execUser := cfg.Sudo.ExecUser
	pamFile := filepath.Join(hostlayout.PamDir, cfg.Sudo.PamService)
	var (
		body []byte
		err  error
	)
	if sudoRs {
		if problem := hostsudo.BranchProblem(execUser, cfg.Sudo.Helper); problem != "" {
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
	if problem := hostsudo.StackProblem(string(body), cfg.Sudo.Helper); problem != "" {
		report.addf("sudo grant", StatusFailed, "%s: %s", pamFile, problem)
		return
	}
	// A block in the shared stack beside a service file of faramir's own: both
	// arrangements are on disk, this sudo reads the service one, and the block is
	// left over. A failure rather than the crossed case above, because the grant
	// beside it names settings written for the other sudo.
	if present, err := hostsudo.BlockPresent(); !sudoRs && !crossed && err == nil && present {
		report.addf("sudo grant", StatusFailed, "a faramir block is still in %s while this host's sudo is the original, which "+
			"selects %s instead: the block is left from an install made when the `sudo` "+
			"alternatives group pointed elsewhere. Re-run `faramir init --allow-sudo`", strings.Join(hostlayout.SudoPamStacks(), " or "), pamFile)
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
		if asaccount.CanWrite(account, cfg.Sudo.Helper) {
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
		if asaccount.CanWrite(account, sudoEnv) {
			report.addf("sudo grant", StatusFailed, "%s can write %s, and %s: it would "+
				"be choosing the environment root is handed", account, sudoEnv, names)
			return
		}
	}
	// The fallback, for the case where the service file is ever removed: a
	// permissive `other` would authenticate anything reaching it.
	if other, err := os.ReadFile(filepath.Join(hostlayout.PamDir, "other")); err == nil {
		if hostsudo.PermissiveAuth(string(other)) {
			report.addf("sudo grant", StatusFailed, "%s/other authenticates without "+
				"asking anything, so removing %s would not close this host's "+
				"escalation but open it. Make the fallback pam_deny",
				hostlayout.PamDir, pamFile)
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
	present, blockErr := hostsudo.BlockPresent()
	if blockErr != nil || !present {
		return nil, pamFile, false, fmt.Sprintf("%s is configured to authenticate "+
			"through %s, which cannot be read (%v): sudo falls back to %s/other for "+
			"that account. Re-run `faramir init --allow-sudo`",
			execUser, pamFile, readErr, hostlayout.PamDir)
	}
	if branch := hostsudo.BranchProblem(execUser, cfg.Sudo.Helper); branch != "" {
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
	if stack == "" || !hostfs.Exists(stack) {
		stack = hostsudo.FirstExistingStack()
	}
	body, err := hostsudo.Block(stack)
	if err != nil {
		return nil, stack, fmt.Sprintf("%s: %v. Re-run `faramir init "+
			"--allow-sudo`", stack, err)
	}
	return body, stack, ""
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
	out, _ := runcmd.OutputWithin(30*time.Second, "sudo", "-l", "-U", account)
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
