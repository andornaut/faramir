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
		GroupID: groupOperator,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			clearUnset(c, &f)
			return codeErr(runInit(f))
		},
	}
	fl := c.Flags()
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as (default: $FARAMIR_OPERATOR, $SUDO_USER, then the current user)")
	fl.StringVar(&f.clientGroup, "client-group", "",
		"group admitted to the broker socket and to enrolled trees (default: installed, then "+
			hostlayout.DefaultClientGroup+")")
	fl.StringVar(&f.secretsGroup, "secrets-group", "",
		"group that owns the ciphertext (default: installed, then the keeper's group)")
	fl.StringVar(&f.brokerUser, "broker-user", "",
		"account the broker runs as (default: installed, then "+hostlayout.DefaultBrokerUser+")")
	fl.StringVar(&f.keeperUser, "keeper-user", "",
		"account that holds the age key (default: installed, then "+hostlayout.DefaultKeeperUser+")")
	fl.StringVar(&f.execUser, "exec-user", "",
		"account brokered commands run as (default: installed, then "+hostlayout.DefaultExecUser+")")
	fl.StringVar(&f.configDir, "config-dir", "",
		"install directory (default: installed, then "+hostlayout.DefaultConfigDir+")")
	fl.StringVar(&f.sshKey, "ssh-key", "",
		"SSH identity lent to brokered commands, minted if missing (default: installed, then id_ed25519 beside the age key)")
	fl.StringVar(&f.knownHosts, "known-hosts", "",
		"known_hosts file to copy for the executor (default: none)")
	fl.StringArrayVar(&f.initAgents, "agent", nil,
		"agent to install deny rules for; repeatable. \""+agentcfg.Auto+"\" (the default) covers every "+
			"agent in the agent account's home. Known: "+strings.Join(agentcfg.Known(), ", "))
	fl.BoolVar(&f.allowSudo, "allow-sudo", false,
		"let a brokered command ask to run sudo; omitting it on a re-run removes the grant")
	fl.StringArrayVar(&f.notifyCommand, "notify-command", nil,
		// The backquoted word is cobra's placeholder for the value, taken from the
		// first one in the string; without it the help reads "stringArray".
		"command announcing a waiting escalation, one `ARG` per flag; \"{prompt}\" or \"{id}\" is "+
			"required. Needs --allow-sudo; omitting it on a re-run keeps the current command")
	fl.BoolVar(&f.repointConfig, "repoint-config", false,
		"allow a --config-dir other than the one the daemons use; the old directory stays on disk, unredacted")
	// The name this had when it read as though init relocated the directory. Kept
	// so a converge that names it keeps working, and hidden so nothing learns it
	// from --help.
	fl.BoolVar(&f.moveConfig, "move-config", false, "renamed to --repoint-config")
	_ = fl.MarkDeprecated("move-config", "use --repoint-config")
	fl.BoolVar(&f.dryRun, "dry-run", false, "report what would change and write nothing")
	fl.BoolVar(&f.asJSON, "json", false, "print the report as JSON")
	// The tunables, named for what they bound rather than for the section they
	// land in.
	command, secret := config.DefaultCommand(), config.DefaultSecret()
	fl.StringArrayVar(&f.commandEnv, "command-env", nil,
		"NAME=VALUE added to every brokered command's environment; repeatable")
	fl.StringVar(&f.commandTimeout, "command-timeout", asDuration(command.TimeoutSec),
		"default command timeout: a duration (90s, 5m) or seconds")
	fl.StringVar(&f.commandMaxTimeout, "command-max-timeout", asDuration(command.MaxTimeoutSec),
		"longest timeout a caller may ask for, and the idle limit on a redact stream")
	fl.IntVar(&f.commandConcurrency, "command-concurrency", command.Concurrency,
		"how many brokered commands may run at once")
	fl.IntVar(&f.commandMaxMemoryPct, "command-max-memory-percent", command.MaxMemoryPercent,
		"MemoryMax on the executor unit, as a share of this machine's memory (1 to 100; 100 is no limit)")
	fl.IntVar(&f.commandMaxProcMB, "command-max-process-memory-mb", command.MaxProcessMemoryMB,
		"LimitDATA on the executor unit, per process (at least 256)")
	fl.StringVar(&f.sudoTimeout, "sudo-timeout", asDuration(config.DefaultSudoTimeoutSec),
		"how long an escalation waits for an answer (1s to 1h, at most --command-max-timeout)")
	fl.IntVar(&f.secretMinLength, "secret-min-length", secret.MinLength,
		"refuse a secret shorter than this (at least 6)")
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
			return nil, fmt.Errorf("--command-env %q: expected NAME=VALUE", pair)
		}
		// The name as well as the shape. A name no shell can reference reached the
		// config either as a TOML key that would not parse, so the run failed with
		// a line number and no mention of the flag, or as one that parsed and left
		// the child holding a variable nothing in it could read.
		if !secretref.ValidEnvName(name) {
			return nil, fmt.Errorf("--command-env %q: not a valid variable name", name)
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
		fmt.Fprintf(os.Stderr, "faramir init: %s; run it outside a brokered command\n", why)
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
		fmt.Fprintf(os.Stderr, "provisioning %s\n", opts.ConfigDir)
	}

	report, err := install.Run(opts)
	// The run's own failure first, then the document: a report that will not
	// marshal must not be the only thing said about an install that failed. The
	// document is printed whether or not the run failed, and a marshal that
	// fails is itself fatal; see printJSON.
	if err != nil {
		reportErr("init", err)
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
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
	if report.BrokerPublicKey != "" {
		fmt.Fprintf(os.Stderr, "broker public key: %s\n", report.BrokerPublicKey)
	}
	if report.DryRun {
		fmt.Fprintln(os.Stderr, "dry run: nothing written")
	}
}
