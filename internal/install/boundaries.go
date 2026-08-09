package install

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
)

// The boundary checks: what each account can and cannot reach once the install
// is on a real host.
//
// Every claim here is one the install steps cannot make.  They check what they
// wrote, and a mode written correctly onto a filesystem that ignores it, a
// socket whose group was replaced afterwards, or an account added to the shared
// group by hand all leave the written answer intact and the boundary gone.
//
// Asked as the uid the claim is about, which is the only way to ask it: root
// bypasses file modes, so the same question from here answers itself.  That is
// what makes root a requirement rather than a convenience.
//
// Negative checks only, plus the few positives whose absence means the install
// does nothing: a boundary that holds is invisible, so nothing else would
// notice it going.

// asUser runs a command as another account and reports its output.
func asUser(account string, args ...string) (string, error) {
	run := &runner{}
	return run.command("runuser", append([]string{"-u", account, "--"}, args...)...)
}

// asOperator runs a command as the account the coding agent runs as, which is
// what the broker's socket admits and root is not.  Directly when this already
// is them: doctor is run both ways and runuser needs root.
func asOperator(opts DoctorOptions, args ...string) (string, error) {
	if os.Geteuid() != 0 || opts.Operator == "" {
		run := &runner{}
		return run.command(args[0], args[1:]...)
	}
	return asUser(opts.Operator, args...)
}

// canRead and canWrite answer access(2) as that account.  Write, not read, is
// what connecting to a unix socket needs, so a socket left 0620 passes a read
// check and is still reachable.
func canRead(account, path string) bool {
	_, err := asUser(account, "test", "-r", path)
	return err == nil
}

func canWrite(account, path string) bool {
	_, err := asUser(account, "test", "-w", path)
	return err == nil
}

// owns reports a file's mode and owner as "%04o account", which is the form the
// findings compare against.  Missing files report "missing".
func owns(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	owner := ownerName(info)
	return fmt.Sprintf("%04o %s", info.Mode().Perm(), owner)
}

// diagnoseBoundaries runs every check that needs a uid other than this one.
func diagnoseBoundaries(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if os.Geteuid() != 0 {
		report.add("boundaries", StatusWarn, "run doctor as root to check these: they "+
			"ask what %s, %s and %s can reach, and no account can answer that for "+
			"another", opts.Operator, opts.BrokerUser, opts.ExecUser)
		return
	}
	// The probe itself, before anything is concluded from what it answers.
	// Every check below reads a refusal as a boundary, so a runuser that cannot
	// run at all would report every one of them as holding, which is the one
	// failure mode worse than not checking.  Every account can read /, so a
	// refusal here is the mechanism rather than the answer.
	if !canRead(opts.KeeperUser, "/") {
		report.add("boundaries", StatusWarn, "cannot ask %s what it can reach, so none "+
			"of these were checked: runuser has to be installed for this",
			opts.KeeperUser)
		return
	}
	diagnoseAgeKey(report, opts, cfg)
	diagnoseStore(report, opts, cfg)
	diagnoseConfigWritable(report, opts)
	diagnoseDenyPatterns(report, opts)
	diagnoseAuditLog(report, opts, cfg)
	diagnoseSockets(report, opts, cfg)
	diagnoseSSHKeys(report, opts, cfg)
	diagnoseProtectProc(report, opts)
	diagnoseBrokered(report, opts)
}

// diagnoseStore checks who can reach the ciphertext.
//
// Membership of the store group is read on every managed file, so the accounts
// that must not hold it are every account that is not the keeper: the operator
// because that is the whole split, the executor because it runs whatever an
// agent asks for, and the broker because it holds the decrypted values already
// and read here would only extend it to files no [secrets] list names.
func diagnoseStore(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if !holds(opts.KeeperUser, opts.StoreGroup) {
		report.add("store", StatusFailed, "%s is not in %s, so it can neither decrypt "+
			"the store nor tell when it changed", opts.KeeperUser, opts.StoreGroup)
		return
	}
	for _, account := range []string{opts.Operator, opts.ExecUser, opts.BrokerUser} {
		if holds(account, opts.StoreGroup) {
			report.add("store", StatusFailed, "%s is in %s, so it can read and replace "+
				"the managed files. Drop it with: gpasswd -d %s %s",
				account, opts.StoreGroup, account, opts.StoreGroup)
			return
		}
	}
	// The directory itself, because the group is only half of it: a store left
	// world-readable is reachable by accounts no group names.
	dir := filepath.Join(opts.ConfigDir, "secrets")
	if cfg != nil && len(cfg.Secrets.Files) > 0 {
		dir = filepath.Dir(cfg.Secrets.Files[0])
	}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o007 != 0 {
		report.add("store", StatusFailed, "%s is %04o: every account on this host can "+
			"reach the ciphertext", dir, info.Mode().Perm())
		return
	}
	if canRead(opts.Operator, dir) {
		report.add("store", StatusFailed, "%s can list %s; the split between asking for "+
			"a value and reading the file it comes from is not in effect",
			opts.Operator, dir)
		return
	}
	report.add("store", StatusOK, "%s is the keeper's, and %s cannot list %s",
		opts.StoreGroup, opts.Operator, dir)
}

// diagnoseConfigWritable checks the file that decides what a brokered command
// runs.  [exec.base_env] PATH is in it, so an account that can write it or drop
// a file in config.d/ chooses the programs the executor resolves, which is the
// one edit that turns the executor into whatever the writer wants.
func diagnoseConfigWritable(report *DoctorReport, opts DoctorOptions) {
	for _, path := range []string{
		filepath.Join(opts.ConfigDir, "config.toml"),
		filepath.Join(opts.ConfigDir, "config.d"),
	} {
		if !exists(path) {
			continue
		}
		if canWrite(opts.Operator, path) {
			report.add("config ownership", StatusFailed, "%s can write %s, which is "+
				"where [exec.base_env] PATH comes from: an edit there chooses what the "+
				"executor runs", opts.Operator, path)
			return
		}
	}
	report.add("config ownership", StatusOK, "%s cannot write the config or its drop-ins",
		opts.Operator)
}

// diagnoseDenyPatterns checks that the shipped deny list was rendered for this
// install rather than copied from another.  The paths in it are this host's, so
// a list naming a directory nothing uses refuses reads of a store that is not
// there and passes every read of the one that is.
func diagnoseDenyPatterns(report *DoctorReport, opts DoctorOptions) {
	path := filepath.Join(DefaultLibexecDir, "deny-patterns.txt")
	body, err := os.ReadFile(path)
	if err != nil {
		report.add("deny patterns", StatusFailed, "%s is missing, so the hook refuses "+
			"nothing: %v", path, err)
		return
	}
	// The paths are interpolated through regexQuote, so a literal dot arrives
	// escaped and the comparison has to be made against that form.
	if !strings.Contains(string(body), regexp.QuoteMeta(opts.ConfigDir)) {
		report.add("deny patterns", StatusFailed, "%s does not name %s, so it was copied "+
			"from another install rather than rendered for this one", path, opts.ConfigDir)
		return
	}
	report.add("deny patterns", StatusOK, "%s names this install's directories", path)
}

// holds is inGroup with the error folded in: an account that cannot be looked
// up is in no group, which is what every caller here does with the error.
func holds(account, group string) bool {
	member, err := inGroup(account, group)
	return err == nil && member
}

// diagnoseAgeKey is the one that stops the examination being worth finishing.
// The key decrypts every managed file retroactively, so an account that can
// read it needs nothing else this protects.
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
	for _, account := range []string{opts.Operator, opts.BrokerUser, opts.ExecUser} {
		if canRead(account, path) {
			report.add("age key", StatusFailed, "%s can read %s, so every file this "+
				"install has ever encrypted is readable by it", account, path)
			return
		}
	}
	report.add("age key", StatusOK, "%s, and only %s can read it", want, opts.KeeperUser)
}

// diagnoseAuditLog checks the record of what ran, which is the operator's
// evidence and therefore worth nothing if the accounts it records can edit it.
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
	for _, account := range []string{opts.Operator, opts.ExecUser} {
		if canRead(account, path) {
			report.add("audit log", StatusFailed, "%s can read %s, so it can also "+
				"truncate what it says", account, path)
			return
		}
	}
	report.add("audit log", StatusOK, "%s, readable by nobody else", want)
}

// diagnoseSockets asks who can open each one.
//
// The keeper's is the age key by another route, and the executor's is a command
// that runs with no policy, no redaction and no audit record.  The broker's is
// the one that has to be reachable: an install nothing can talk to protects
// everything and does nothing.
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
		{"keeper socket", cfg.Keeper.SocketPath, []string{opts.Operator, opts.ExecUser},
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor socket", cfg.Executor.SocketPath, []string{opts.Operator, opts.ExecUser},
			"a command sent there runs unredacted and unlogged"},
	}
	for _, socket := range closed {
		if socket.path == "" || !exists(socket.path) {
			continue
		}
		reached := false
		for _, account := range socket.accounts {
			if canWrite(account, socket.path) {
				report.add(socket.name, StatusFailed, "%s can open %s: %s",
					account, socket.path, socket.cost)
				reached = true
			}
		}
		if !reached {
			report.add(socket.name, StatusOK, "%s is closed to %s", socket.path,
				strings.Join(socket.accounts, " and "))
		}
	}
	if path := cfg.Server.SocketPath; path != "" && exists(path) {
		if canWrite(opts.Operator, path) {
			report.add("broker socket", StatusOK, "%s can open %s", opts.Operator, path)
		} else {
			report.add("broker socket", StatusFailed, "%s cannot open %s, so nothing "+
				"it runs is brokered. Membership of %s is what grants this",
				opts.Operator, path, opts.Group)
		}
	}
}

// diagnoseSSHKeys covers what the agent is for: the executor authenticates to
// managed hosts and never holds a key.  Both halves matter, and the private
// socket is the one that would hand it the whole agent protocol rather than the
// list and sign the relay forwards.
func diagnoseSSHKeys(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || len(cfg.Ssh.Keys) == 0 {
		return
	}
	for _, key := range cfg.Ssh.Keys {
		if !exists(key) {
			continue
		}
		if canRead(opts.ExecUser, key) {
			report.add("ssh keys", StatusFailed, "%s can read %s, so the agent buys "+
				"nothing: a brokered command can take the key itself", opts.ExecUser, key)
			return
		}
	}
	if private := cfg.Ssh.AgentSocket + ".private"; exists(private) &&
		canWrite(opts.ExecUser, private) {
		report.add("ssh keys", StatusFailed, "%s can open %s, which is ssh-agent's own "+
			"socket: that bypasses the relay and the whole agent protocol is reachable",
			opts.ExecUser, private)
		return
	}
	report.add("ssh keys", StatusOK, "%s can use the agent and read no key held by it",
		opts.ExecUser)
}

// diagnoseProtectProc checks the setting that keeps a value out of the one place
// a running daemon still shows it.  A brokered command's value is in the
// executor's environment for as long as it runs, and /proc is where another
// account would read it.
func diagnoseProtectProc(report *DoctorReport, opts DoctorOptions) {
	pid := mainPID("faramir-broker.service")
	if pid == "" {
		report.add("protectproc", StatusWarn, "the broker is not running, so what "+
			"/proc shows of it cannot be checked")
		return
	}
	environ := filepath.Join("/proc", pid, "environ")
	if canRead(opts.Operator, environ) {
		report.add("protectproc", StatusFailed, "%s can read %s; ProtectProc is not "+
			"in effect and a running command's value is readable there",
			opts.Operator, environ)
		return
	}
	report.add("protectproc", StatusOK, "%s cannot read the broker's environ", opts.Operator)
}

// mainPID asks systemd rather than matching a process name, which is the same
// question without the guesswork about what the binary is called.
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

// diagnoseBrokered asks the broker to run something and looks at what came
// back.  Everything above is about what an account can reach; this is the one
// place the answer is what a brokered command actually gets.
//
// As the operator, because the broker checks the peer's credentials: root is
// not in the shared group either, so asking as ourselves would report a broken
// install on a working one.
func diagnoseBrokered(report *DoctorReport, opts DoctorOptions) {
	faramir := filepath.Join(DefaultBinDir, "faramir")
	brokered := func(args ...string) (string, error) {
		return asUser(opts.Operator, append([]string{faramir, "run", "--quiet", "--"}, args...)...)
	}
	out, err := brokered("id", "-un")
	if err != nil {
		report.add("brokered command", StatusFailed, "%s could not run one: %v",
			opts.Operator, err)
		return
	}
	if got := strings.TrimSpace(out); got != opts.ExecUser {
		report.add("brokered command", StatusFailed, "runs as %s, expected %s: it is "+
			"holding whatever that account can reach", got, opts.ExecUser)
		return
	}
	// The keeper is handed the key through LoadCredential=, so the credential
	// directory and the environment are the two places a child might still find
	// it.  Both are asked through a shell, being a glob and an expansion.
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
		// Reported without the output: whatever was read is the thing this is
		// checking for, and a finding that quotes it has published it.
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

// diagnoseRedaction is the end-to-end claim: a managed value, injected into a
// real command on this host, comes back as its token.  Everything else here is
// about reachability; this is the one check that fails when redaction itself
// has stopped working.
//
// The value is never in a finding, on any path.  A failure means the plaintext
// is in that output, so what gets reported is that no token appeared.
func diagnoseRedaction(report *DoctorReport, opts DoctorOptions) {
	faramir := filepath.Join(DefaultBinDir, "faramir")
	out, err := asOperator(opts, faramir, "list-secrets")
	if err != nil {
		report.add("redaction", StatusWarn, "could not list the refs to probe with: %v", err)
		return
	}
	ref := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	if ref == "" {
		report.add("redaction", StatusWarn, "no managed refs to probe with, so nothing "+
			"here proves redaction runs")
		return
	}
	probe, err := asOperator(opts, faramir, "run", "--quiet",
		"--env", "FARAMIR_DOCTOR_PROBE="+ref, "--", "printenv", "FARAMIR_DOCTOR_PROBE")
	if err != nil {
		report.add("redaction", StatusWarn, "could not run the probe: %v", err)
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

// ownerName is the account a file belongs to, falling back to the numeric uid
// for one nothing on this host names.
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
