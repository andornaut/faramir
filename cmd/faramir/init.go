package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/secretref"
)

type initFlags struct {
	agentUser     string
	clientGroup   string
	secretsGroup  string
	brokerUser    string
	keeperUser    string
	execUser      string
	configDir     string
	sshKey        string
	knownHosts    string
	initAgents    []string
	allowSudo     bool
	notifyCommand []string
	repointConfig bool
	moveConfig    bool
	dryRun        bool
	asJSON        bool

	// The tunables. Each flag's default is the real one, so --help says what a
	// host gets; clearUnset then blanks the ones nobody typed, a value left out
	// meaning "keep what the install has".
	commandEnv []string
	// The three durations are strings, so a caller may write 5m as well as 300.
	// Parsed once in runInit, which is where a bad spelling is refused.
	commandTimeout      string
	commandMaxTimeout   string
	commandConcurrency  int
	commandMaxMemoryPct int
	commandMaxProcMB    int
	sudoTimeout         string
	secretMinLength     int
}

// tunables maps each flag to where it lands, for clearUnset. One table, so a
// flag added to the struct and not here is one that silently reverts the
// install every run.
func (f *initFlags) tunables() map[string]func() {
	return map[string]func(){
		"command-timeout":               func() { f.commandTimeout = "" },
		"command-max-timeout":           func() { f.commandMaxTimeout = "" },
		"command-concurrency":           func() { f.commandConcurrency = 0 },
		"command-max-memory-percent":    func() { f.commandMaxMemoryPct = 0 },
		"command-max-process-memory-mb": func() { f.commandMaxProcMB = 0 },
		"sudo-timeout":                  func() { f.sudoTimeout = "" },
		"secret-min-length":             func() { f.secretMinLength = 0 },
	}
}

// clearUnset blanks every tunable the operator did not name, so a value left
// out means "keep what the install has". Zero is the unset signal, which is
// why no tunable takes zero as a legal value.
func clearUnset(c *cobra.Command, f *initFlags) {
	for name, clear := range f.tunables() {
		if !c.Flags().Changed(name) {
			clear()
		}
	}
}

func newInitCmd() *cobra.Command {
	var f initFlags
	c := &cobra.Command{
		Use:     "init [options]",
		Short:   "Install or re-install faramir on this host",
		GroupID: groupProvisioning,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			clearUnset(c, &f)
			return codeErr(runInit(f))
		},
	}
	fl := c.Flags()
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as; the operator's own account. Only init "+
			"takes it, and every other command reads what init recorded "+
			"(default: $FARAMIR_OPERATOR, then $SUDO_USER, then the current user)")
	// One admits a caller to the broker socket and shares the working tree, the
	// other owns the ciphertext; holding one is not holding the other.
	fl.StringVar(&f.clientGroup, "client-group", "",
		"group admitted to the broker socket, and given access to an enrolled working "+
			"tree (default: what the install uses, then "+hostlayout.DefaultClientGroup+")")
	fl.StringVar(&f.secretsGroup, "secrets-group", "",
		"group that owns the ciphertext in <config-dir>/secrets; naming a group other "+
			"than the keeper's adds a second reader (default: what the install uses, then "+
			"the keeper's own group)")
	fl.StringVar(&f.brokerUser, "broker-user", "",
		"account that holds the SSH keys and the audit log (default: what the install "+
			"uses, then "+hostlayout.DefaultBrokerUser+")")
	fl.StringVar(&f.keeperUser, "keeper-user", "",
		"account that holds the age key (default: what the install uses, then "+
			hostlayout.DefaultKeeperUser+")")
	fl.StringVar(&f.execUser, "exec-user", "",
		"account brokered commands run as (default: what the install uses, then "+
			hostlayout.DefaultExecUser+")")
	fl.StringVar(&f.configDir, "config-dir", "",
		"where config.toml, the age key and the managed sops files are "+
			"installed (default: ask the broker, then read its unit, then "+hostlayout.DefaultConfigDir+")")
	fl.StringVar(&f.sshKey, "ssh-key", "",
		"path of the SSH identity the broker lends to brokered commands; it is "+
			"minted if missing (default: what the install uses, then id_ed25519 beside "+
			"the age key)")
	fl.StringVar(&f.knownHosts, "known-hosts", "",
		"a known_hosts file to copy to <exec-home>/.ssh/known_hosts for the executor "+
			"(default: none; only /etc/ssh/ssh_known_hosts is used)")
	fl.StringArrayVar(&f.initAgents, "agent", nil,
		"coding agent to install the deny rules for; repeatable. \""+agentcfg.Auto+"\" "+
			"(the default) means every agent the agent account's home already has. A name "+
			"installs them whether or not the agent is there, and can be combined with "+
			"auto. Known: "+strings.Join(agentcfg.Known(), ", "))
	fl.BoolVar(&f.allowSudo, "allow-sudo", false,
		"let a brokered command ask to run sudo. Each request is approved by a person "+
			"with 'faramir sudo approve'; there is no password. Off by default, and "+
			"re-running init without it removes the grant")
	fl.StringArrayVar(&f.notifyCommand, "notify-command", nil,
		// The backquoted word is cobra's placeholder for the value, taken from the
		// first one in the string; without it the help reads "stringArray".
		"command that announces a waiting sudo request, one `ARG` per flag: "+
			"--notify-command /usr/bin/wall --notify-command '{prompt}'. One of \"{prompt}\" "+
			"and \"{id}\" is required; do not pass \"{id}\" to anything that broadcasts. The "+
			"program is found on PATH and runs inside the broker unit's sandbox. Needs "+
			"--allow-sudo. A re-run that omits it keeps the current command; naming it "+
			"replaces the whole list")
	fl.BoolVar(&f.repointConfig, "repoint-config", false,
		"allow a different --config-dir than the one the daemons use now. Nothing is "+
			"moved: the old directory's age key and ciphertext stay on disk, and the "+
			"refs it served are no longer redacted. Without this flag a new "+
			"--config-dir is refused")
	// The name this had when it read as though init relocated the directory. Kept
	// so a converge that names it keeps working, and hidden so nothing learns it
	// from --help.
	fl.BoolVar(&f.moveConfig, "move-config", false, "renamed to --repoint-config")
	_ = fl.MarkDeprecated("move-config", "use --repoint-config: nothing is moved, "+
		"the daemons are pointed at the new directory and the old one stays on disk")
	fl.BoolVar(&f.dryRun, "dry-run", false, "report what would change and write nothing")
	fl.BoolVar(&f.asJSON, "json", false, "print the report as JSON")
	// The tunables, named for what they bound rather than for the section they
	// land in.
	command, secret := config.DefaultCommand(), config.DefaultSecret()
	fl.StringArrayVar(&f.commandEnv, "command-env", nil,
		"NAME=VALUE to add to every brokered command's environment; repeatable, and added to the built-in table")
	fl.StringVar(&f.commandTimeout, "command-timeout", asDuration(command.TimeoutSec),
		"timeout for a command whose request names none: a duration such as 5m, or a number of seconds")
	fl.StringVar(&f.commandMaxTimeout, "command-max-timeout", asDuration(command.MaxTimeoutSec),
		"the longest timeout a caller may ask for, and the idle limit on a redact stream: a duration, or a number of seconds")
	fl.IntVar(&f.commandConcurrency, "command-concurrency", command.Concurrency,
		"how many brokered commands may run at once; further requests are refused as busy")
	fl.IntVar(&f.commandMaxMemoryPct, "command-max-memory-percent", command.MaxMemoryPercent,
		"the share of this machine's memory all brokered commands together may use, as MemoryMax on the executor unit (1 to 100). A cgroup total, so it counts every child process and page cache; 100 is no limit")
	fl.IntVar(&f.commandMaxProcMB, "command-max-process-memory-mb", command.MaxProcessMemoryMB,
		"how much one brokered process may allocate, as LimitDATA on the executor unit (at least 256). Anonymous memory only, not page cache; a process that reaches it gets an allocation failure rather than the OOM killer")
	fl.StringVar(&f.sudoTimeout, "sudo-timeout", asDuration(config.DefaultSudoTimeoutSec),
		"how long a sudo request waits for an answer before it is refused (1s to 1h, and at most --command-max-timeout, since the command waits inside sudo the whole time)")
	fl.IntVar(&f.secretMinLength, "secret-min-length", secret.MinLength,
		"refuse a secret shorter than this, since a short value would match inside ordinary words (at least 6)")
	return c
}

// namedValues turns repeated NAME=VALUE flags into the table they describe. A
// value may hold "=", so only the first one separates.
func namedValues(pairs []string) (map[string]string, error) {
	// Empty rather than nil for no pairs: the caller merges this over the
	// built-in table either way.
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		name, value, found := strings.Cut(pair, "=")
		if !found {
			// Blocked rather than skipped: `--command-env FOO` reads as setting
			// something, and accepting it would leave the child without it and no
			// reason given.
			return nil, fmt.Errorf("--command-env %q names no value; write it as NAME=VALUE", pair)
		}
		// The name as well as the shape. A name no shell can reference reached the
		// config either as a TOML key that would not parse, so the run failed with
		// a line number and no mention of the flag, or as one that parsed and left
		// the child holding a variable nothing in it could read.
		if !secretref.ValidEnvName(name) {
			return nil, fmt.Errorf("--command-env %q is not a usable environment "+
				"variable name: a letter or underscore, then letters, digits and "+
				"underscores", name)
		}
		out[name] = value
	}
	return out, nil
}

func runInit(f initFlags) int {
	// Before the first step. init asks the broker what the agent holds on its way
	// out, so nested it would do every other step and then fail at its own
	// verification: a converge that changed nothing and reports failure, with
	// nothing in the ending to point at the cause.
	if why := protocol.NestedRun(); why != "" {
		fmt.Fprintf(os.Stderr, "faramir init: %s, so its last step would be refused. "+
			"Run it from your own shell\n", why)
		return 1
	}

	env, err := namedValues(f.commandEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir init: %v\n", err)
		return 2
	}

	// The durations, refused here rather than carried into the config as a zero.
	// Zero is the unset signal every tunable shares, so a spelling this could not
	// read would otherwise land as "keep what the install has".
	durations := map[string]*string{
		"--command-timeout":     &f.commandTimeout,
		"--command-max-timeout": &f.commandMaxTimeout,
		"--sudo-timeout":        &f.sudoTimeout,
	}
	seconds := make(map[string]int, len(durations))
	for flag, value := range durations {
		got, err := durationSeconds(flag, *value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir init: %v\n", err)
			return 2
		}
		seconds[flag] = got
	}

	opts := install.Options{
		// The accounts this run is naming as well as the ones already installed:
		// `init` is what writes the units, so on a first install there are none to
		// read and the compiled-in names are all InstalledAccounts can offer. A
		// host installed with --exec-user would then not refuse the account it is
		// about to create.
		AgentUser: operatorName(
			notTheOperator(f.brokerUser, f.keeperUser, f.execUser), f.agentUser),
		ClientGroup:   f.clientGroup,
		SecretsGroup:  f.secretsGroup,
		BrokerUser:    f.brokerUser,
		KeeperUser:    f.keeperUser,
		ExecUser:      f.execUser,
		ConfigDir:     initConfigDir(f.configDir, socketDefault()),
		SSHKey:        f.sshKey,
		KnownHosts:    f.knownHosts,
		Agents:        f.initAgents,
		AllowSudo:     f.allowSudo,
		NotifyCommand: f.notifyCommand,

		CommandEnv:                env,
		CommandTimeoutSec:         seconds["--command-timeout"],
		CommandMaxTimeoutSec:      seconds["--command-max-timeout"],
		CommandConcurrency:        f.commandConcurrency,
		CommandMaxMemoryPercent:   f.commandMaxMemoryPct,
		CommandMaxProcessMemoryMB: f.commandMaxProcMB,
		SudoTimeoutSec:            seconds["--sudo-timeout"],
		SecretMinLength:           f.secretMinLength,
		// Either spelling: the old one is deprecated rather than gone, so a fleet
		// that has not been edited yet still installs.
		RepointConfig: f.repointConfig || f.moveConfig,
		DryRun:        f.dryRun,
	}
	// Progress goes to stderr so --json owns stdout, and is suppressed under
	// --json entirely.
	if !f.asJSON {
		opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
		// Named before anything is written: without --config-dir this was
		// discovered, and an install written somewhere the operator did not expect
		// is a second install rather than an error.
		fmt.Fprintf(os.Stderr, "faramir init: provisioning the install at %s\n", opts.ConfigDir)
	}

	report, err := install.Run(opts)
	// The run's own failure first, then the document: a report that will not
	// marshal must not be the only thing said about an install that failed. The
	// document is printed whether or not the run failed, and a marshal that
	// fails is itself fatal; see printJSON.
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir init: %v\n", err)
	}
	if f.asJSON {
		if code := printJSON("init", report); code != 0 {
			return code
		}
	}
	if err != nil {
		return 1
	}
	if !f.asJSON {
		reportToOperator(report)
	}
	return 0
}

// reportToOperator prints what a person needs after a run: what installs
// cleanly and then does not work, and the public key the fleet must
// authorize.
func reportToOperator(report install.Report) {
	for _, warning := range report.Warnings {
		fmt.Fprintf(os.Stderr, "\nWARNING: %s\n", warning)
	}
	if report.BrokerPublicKey != "" {
		fmt.Fprintf(os.Stderr, "\nThe broker's public key:\n  %s\n", report.BrokerPublicKey)
		fmt.Fprintln(os.Stderr, "Put it in ~/.ssh/authorized_keys on every managed host, "+
			"for the account you connect as.")
	}
	if report.DryRun {
		fmt.Fprintln(os.Stderr, "\nDry run: nothing was written.")
	}
}
