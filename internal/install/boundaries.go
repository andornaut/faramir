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

// The boundary checks: what each account can and cannot reach on a real host.
// The install steps can only check what they wrote, and a mode on a filesystem
// that ignores it, a socket regrouped afterwards, or an account added to the
// shared group by hand all leave the written answer intact.
//
// Asked as the uid the claim is about, root bypassing file modes, which is what
// makes root a requirement here.  Negative checks only, plus the few positives
// whose absence means the install does nothing.

// asUser runs a command as another account and reports its output.
func asUser(account string, args ...string) (string, error) {
	run := &runner{}
	return run.command("runuser", append([]string{"-u", account, "--"}, args...)...)
}

// asOperator runs a command as the account the broker's socket admits, root not
// being in that group.  Directly when this already is them, runuser needing
// root.
func asOperator(opts DoctorOptions, args ...string) (string, error) {
	if os.Geteuid() != 0 || opts.OperatorUser == "" {
		run := &runner{}
		return run.command(args[0], args[1:]...)
	}
	return asUser(opts.OperatorUser, args...)
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

// owns reports a file's mode and owner as "%04o account", or "missing".
func owns(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	owner := ownerName(info)
	return fmt.Sprintf("%04o %s", info.Mode().Perm(), owner)
}

// diagnoseBoundaries runs every check that needs a uid other than this one.
//
// Held as a list so a run that skips them can say how many went unasked: the
// single warn line below stands for all of them, and a count taken from the
// list cannot drift from what is in it.
func diagnoseBoundaries(report *DoctorReport, opts DoctorOptions, cfg *config.Config, serves brokerServes) {
	checks := []func(){
		func() { diagnoseAgeKey(report, opts, cfg) },
		func() { diagnoseOperatorKeys(report, opts) },
		func() { diagnoseStore(report, opts, cfg) },
		func() { diagnoseConfigWritable(report, opts) },
		func() { diagnoseInstalledFiles(report, opts) },
		func() { diagnoseDenyPatterns(report, opts) },
		func() { diagnoseAuditLog(report, opts, cfg) },
		func() { diagnoseSockets(report, opts, cfg) },
		func() { diagnoseSocketPolicy(report, opts, cfg) },
		func() { diagnoseSSHKey(report, opts, cfg) },
		func() { diagnoseProtectProc(report, opts) },
		func() { diagnoseBrokered(report, opts, serves) },
	}
	if os.Geteuid() != 0 {
		report.NotAsked += len(checks)
		report.add("boundaries", StatusWarn, "run doctor as root to check these: %d checks "+
			"ask what %s, %s and %s can reach, and no account can answer that for "+
			"another", len(checks), opts.OperatorUser, opts.BrokerUser, opts.ExecUser)
		return
	}
	// The probe itself: every check below reads a refusal as a boundary, so a
	// runuser that cannot run would report all of them as holding.  Every account
	// can read /, so a refusal here is the mechanism.
	if !canRead(opts.KeeperUser, "/") {
		report.NotAsked += len(checks)
		report.add("boundaries", StatusWarn, "cannot ask %s what it can reach, so none "+
			"of these %d checks were made: runuser has to be installed for this",
			opts.KeeperUser, len(checks))
		return
	}
	for _, check := range checks {
		check()
	}
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
	for _, account := range []string{opts.OperatorUser, opts.ExecUser, opts.BrokerUser} {
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
	if cfg != nil && len(cfg.Secrets.Files) > 0 {
		dir = filepath.Dir(cfg.Secrets.Files[0])
	}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o007 != 0 {
		report.add("secrets", StatusFailed, "%s is %04o: every account on this host can "+
			"reach the ciphertext", dir, info.Mode().Perm())
		return
	}
	if canRead(opts.OperatorUser, dir) {
		report.add("secrets", StatusFailed, "%s can list %s; the split between asking for "+
			"a value and reading the file it comes from is not in effect",
			opts.OperatorUser, dir)
		return
	}
	report.add("secrets", StatusOK, "%s is the keeper's, and %s cannot list %s",
		opts.SecretsGroup, opts.OperatorUser, dir)
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
		if canWrite(opts.OperatorUser, path) {
			report.add("config ownership", StatusFailed, "%s can write %s, which is "+
				"where [exec.base_env] PATH comes from: an edit there chooses what the "+
				"executor runs", opts.OperatorUser, path)
			return
		}
	}
	report.add("config ownership", StatusOK, "%s cannot write the config or its drop-ins",
		opts.OperatorUser)
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
	}
	for _, path := range enforcers {
		if !exists(path) {
			report.add("installed files", StatusFailed, "%s is missing", path)
			return
		}
		// The directory too: write there is permission to replace what is in it.
		if canWrite(opts.OperatorUser, path) {
			report.add("installed files", StatusFailed, "%s can write %s, so it can "+
				"replace what enforces the deny list rather than having to get past it",
				opts.OperatorUser, path)
			return
		}
	}
	report.add("installed files", StatusOK, "%s cannot write the binary, the deny list "+
		"or the wrapper", opts.OperatorUser)
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
	for _, account := range []string{opts.OperatorUser, opts.BrokerUser, opts.ExecUser} {
		if canRead(account, path) {
			report.add("age key", StatusFailed, "%s can read %s, so every file this "+
				"install has ever encrypted is readable by it", account, path)
			return
		}
	}
	report.add("age key", StatusOK, "%s, and only %s can read it", want, opts.KeeperUser)
}

// diagnoseOperatorKeys checks what enrolling a tree granted.  init-project
// makes every directory from the home down to the tree traversable by the
// client group, which faramir-exec is in; traversal is execute without read, so
// only the enrolled tree is shared.  A home that was itself enrolled is
// group-readable throughout, which carries the operator's SSH keys and the age
// key under ~/.config/sops -- a second copy of the same authority, which the
// check above cannot see.
func diagnoseOperatorKeys(report *DoctorReport, opts DoctorOptions) {
	// No name to ask about is how doctor was invoked: operatorName falls back to
	// SUDO_USER and then to the caller, and a root login shell, a cron job or a
	// systemd timer has neither.  Nothing about the install is wrong.
	if opts.OperatorUser == "" {
		report.add("operator keys", StatusWarn, "no operator account to ask about: "+
			"run under sudo so SUDO_USER carries it, or pass --operator-user")
		return
	}
	// A name that was given and does not resolve is different: it is the name
	// every other finding here is about, so a pass below would be about nobody.
	entry, err := user.Lookup(opts.OperatorUser)
	if err != nil || entry.HomeDir == "" {
		report.add("operator keys", StatusFailed, "%s does not resolve to an account "+
			"with a home (%v), and it is the name every check here is about. Pass "+
			"--operator-user", opts.OperatorUser, err)
		return
	}
	home := filepath.Clean(entry.HomeDir)
	if !exists(home) {
		// An encrypted home is absent until its owner logs in, which is a state
		// this install is designed for rather than a fault.
		report.add("operator keys", StatusWarn, "%s does not exist, so what a brokered "+
			"command can read in it was not checked", home)
		return
	}
	if canRead(opts.ExecUser, home) {
		report.add("operator keys", StatusFailed, "%s can list %s: the home was enrolled "+
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
			report.add("operator keys", StatusFailed, "%s can read %s, so a brokered "+
				"command holds whatever is in it", opts.ExecUser, path)
			return
		}
	}
	report.add("operator keys", StatusOK, "%s can traverse %s and read nothing in it",
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
	for _, account := range []string{opts.OperatorUser, opts.ExecUser} {
		if canRead(account, path) {
			report.add("audit log", StatusFailed, "%s can read %s, so it can also "+
				"truncate what it says", account, path)
			return
		}
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
		{"keeper socket", cfg.Keeper.SocketPath, []string{opts.OperatorUser, opts.ExecUser},
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor socket", cfg.Executor.SocketPath, []string{opts.OperatorUser, opts.ExecUser},
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
		if canWrite(opts.OperatorUser, path) {
			report.add("broker socket", StatusOK, "%s can open %s", opts.OperatorUser, path)
		} else {
			report.add("broker socket", StatusFailed, "%s cannot open %s, so nothing "+
				"it runs is brokered. Membership of %s is what grants this",
				opts.OperatorUser, path, opts.ClientGroup)
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
	if key := cfg.Ssh.Key; exists(key) {
		if canRead(opts.ExecUser, key) {
			report.add("ssh key", StatusFailed, "%s can read %s, so the agent buys "+
				"nothing: a brokered command can take the key itself", opts.ExecUser, key)
			return
		}
		// The operator too, and for the same reason: the coding agent runs as that
		// account, so a key it can read is one that reaches the model's context by
		// any route the deny patterns miss.  init asserts the mode; this is what
		// catches a chmod afterwards.
		if canRead(opts.OperatorUser, key) {
			report.add("ssh key", StatusFailed, "%s can read %s, and the coding agent "+
				"runs as that account: the key is readable by the thing the agent "+
				"was meant to keep it from", opts.OperatorUser, key)
			return
		}
	}
	if private := cfg.Ssh.AgentSocket + ".private"; exists(private) &&
		canWrite(opts.ExecUser, private) {
		report.add("ssh key", StatusFailed, "%s can open %s, which is ssh-agent's own "+
			"socket: that bypasses the relay and the whole agent protocol is reachable",
			opts.ExecUser, private)
		return
	}
	report.add("ssh key", StatusOK, "%s and %s can use the agent and read no key "+
		"held by it", opts.OperatorUser, opts.ExecUser)
}

// diagnoseProtectProc: a brokered command's value is in the executor's
// environment while it runs, and /proc is where another account would read it.
func diagnoseProtectProc(report *DoctorReport, opts DoctorOptions) {
	pid := mainPID("faramir-broker.service")
	if pid == "" {
		// Warn, not fail: the unit is socket-activated, so idle is its resting
		// state, and a broker that cannot be reached at all is already reported by
		// the socket check and the broker probe.
		report.add("protectproc", StatusWarn, "the broker is not running, so what "+
			"/proc shows of it cannot be checked")
		return
	}
	environ := filepath.Join("/proc", pid, "environ")
	if canRead(opts.OperatorUser, environ) {
		report.add("protectproc", StatusFailed, "%s can read %s; ProtectProc is not "+
			"in effect and a running command's value is readable there",
			opts.OperatorUser, environ)
		return
	}
	report.add("protectproc", StatusOK, "%s cannot read the broker's environ", opts.OperatorUser)
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
	// Running one against a refusing broker would report the refusal as a broken
	// boundary.  That state is a failure already, reported where it belongs.
	//
	// Reached as root, so an unestablished value set means --check itself did not
	// report, which is a distinct reason and not the broker's answer.
	switch serves {
	case servesNothing:
		report.NotAsked++
		report.add("brokered command", StatusWarn, "not asked: the broker has read "+
			"no managed file, so it refuses the command this would run")
		return
	case servesUnknown:
		report.NotAsked++
		report.add("brokered command", StatusWarn, "not asked: --check did not report, "+
			"so whether the broker would refuse the command this runs is unknown")
		return
	}
	// The other way the command cannot be sent, and the state doctor is run in on
	// purpose: a broker that answered nothing when the install was looked up is
	// one no brokered command reaches, and running one here would report a
	// stopped install as a boundary that does not hold.  The outage is the
	// sockets and version checks' to report.
	if opts.BrokerVersion == "" {
		report.NotAsked++
		report.add("brokered command", StatusWarn, "not asked: the broker did not "+
			"answer, so the command this runs cannot be sent")
		return
	}
	faramir := filepath.Join(DefaultBinDir, "faramir")
	brokered := func(args ...string) (string, error) {
		return asUser(opts.OperatorUser, append([]string{faramir, "run", "--quiet", "--"}, args...)...)
	}
	out, err := brokered("id", "-un")
	if err != nil {
		report.add("brokered command", StatusFailed, "%s could not run one: %v",
			opts.OperatorUser, err)
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
// path -- a failure means the plaintext is in that output, so what is reported
// is that no token appeared.
func diagnoseRedaction(report *DoctorReport, opts DoctorOptions) {
	faramir := filepath.Join(DefaultBinDir, "faramir")
	out, err := asOperator(opts, faramir, "list-secrets")
	if err != nil {
		report.add("redaction", StatusFailed, "could not list the refs to probe with: %v", err)
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
