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
		"account the coding agent runs as, which is the one this host belongs to. "+
			"The only command that names it; everything else reads what this "+
			"records (default $FARAMIR_OPERATOR, then $SUDO_USER, then you)")
	// One admits a caller to the broker socket and shares the working tree, the
	// other owns the ciphertext; holding one is not holding the other.
	fl.StringVar(&f.clientGroup, "client-group", "",
		"group admitted to the broker socket, and shared with the executor on a working "+
			"tree (default: what the install uses, then "+hostlayout.DefaultClientGroup+")")
	fl.StringVar(&f.secretsGroup, "secrets-group", "",
		"group owning the ciphertext in <config-dir>/secrets (default: what the install uses, then the keeper's own group, which is the only account that opens one; naming another adds a second reader)")
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
		"where the identity the broker lends to brokered commands lives "+
			"(default: what the install uses, then id_ed25519 beside the age key; "+
			"one is minted either way)")
	fl.StringVar(&f.knownHosts, "known-hosts", "",
		"host keys pinned for the executor, copied to <exec-home>/.ssh/known_hosts "+
			"(default: none, verifying against /etc/ssh/ssh_known_hosts alone)")
	fl.StringArrayVar(&f.initAgents, "agent", nil,
		"install the deny rules into this agent's own settings, repeatable. "+
			"Default \""+agentcfg.Auto+"\": whichever agents the agent account's home "+
			"already carries. A name writes them whether or not the agent is there, "+
			"and composes with auto. Known: "+
			strings.Join(agentcfg.Known(), ", "))
	fl.BoolVar(&f.allowSudo, "allow-sudo", false,
		"let a brokered command ASK to sudo; it cannot sudo on its own. A human approves "+
			"each through 'faramir sudo approve', and no password exists anywhere. Off by "+
			"default; re-running without it takes the grant away")
	fl.StringArrayVar(&f.notifyCommand, "notify-command", nil,
		// The backquoted word is cobra's placeholder for the value, taken from the
		// first one in the string; without it the help reads "stringArray".
		"announce a waiting escalation: one `ARG` each, repeatable, --notify-command "+
			"/usr/bin/wall --notify-command '{prompt}'. One of \"{prompt}\" and \"{id}\" must "+
			"appear; keep \"{id}\" off anything that broadcasts. The program is resolved on "+
			"PATH and runs inside the broker unit's sandbox. Needs --allow-sudo. Kept "+
			"across a re-run that does not name it; naming it replaces the whole list")
	fl.BoolVar(&f.repointConfig, "repoint-config", false,
		"consent to point this host's daemons at a different --config-dir. Nothing is "+
			"moved: the new directory replaces the old, so the refs the old one served "+
			"stop being redacted while its age key and ciphertext stay on disk where "+
			"they are. Blocked without this")
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
		"NAME=VALUE in a brokered command's environment; repeatable, and it adds to the built-in table rather than replacing it")
	fl.StringVar(&f.commandTimeout, "command-timeout", asDuration(command.TimeoutSec),
		"how long a command runs when the request names no timeout: a duration such as 5m, or a bare number of seconds")
	fl.StringVar(&f.commandMaxTimeout, "command-max-timeout", asDuration(command.MaxTimeoutSec),
		"the most a caller may ask for, and the idle bound on a redact stream: a duration, or a bare number of seconds")
	fl.IntVar(&f.commandConcurrency, "command-concurrency", command.Concurrency,
		"how many brokered commands run at once; the rest are refused busy. Held to what the executor forks at once")
	fl.IntVar(&f.commandMaxMemoryPct, "command-max-memory-percent", command.MaxMemoryPercent,
		"the backstop: how much of this machine's memory every brokered command together may hold, as MemoryMax on the executor unit (1 to 100). It is a cgroup total, so it catches fan-out that no per-process limit sees, and it counts page cache; 100 is the whole machine, which is no bound")
	fl.IntVar(&f.commandMaxProcMB, "command-max-process-memory-mb", command.MaxProcessMemoryMB,
		"what one brokered process may allocate, as LimitDATA on the executor unit (at least 256). Anonymous memory only, so a command is not charged for page cache, and one that reaches it gets an allocation failure it can report rather than the OOM killer")
	fl.StringVar(&f.sudoTimeout, "sudo-timeout", asDuration(config.DefaultSudoTimeoutSec),
		"how long a sudo question waits for a human before it is refused (1s to 1h, and never more than --command-max-timeout: the command waits inside sudo for the whole question)")
	fl.IntVar(&f.secretMinLength, "secret-min-length", secret.MinLength,
		"refuse a secret shorter than this: it cannot be redacted without matching inside ordinary words (at least 6)")
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
		if !protocol.ValidEnvName(name) {
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
		fmt.Fprintf(os.Stderr, "faramir init: %s, so init cannot finish: it asks the broker what the agent holds "+
			"and that question would be refused. Run it from a shell of your own\n", why)
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
		fmt.Fprintln(os.Stderr, "It must be in ~/.ssh/authorized_keys for the account you "+
			"connect as on every managed host, or brokered commands authenticate as nobody.")
	}
	if report.DryRun {
		fmt.Fprintln(os.Stderr, "\nDry run: nothing was written.")
	}
}
