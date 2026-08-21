package main

// The subcommands that provision and inspect a host. They act on files rather
// than through the broker, but they ask a running one where the install is; see
// askBroker.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// brokerUnit records the config the daemons loaded. A variable so a test can
// point it at a fixture, and taken from install rather than written out again:
// init refuses a config move against the same file.
var brokerUnit = install.UnitPath("faramir-broker.service")

// status is what a running broker says about itself: where its config is, and
// which build is answering.
type status struct {
	configDir string
	version   string
}

// askBroker asks a running broker about itself in one round trip, and returns a
// zero status on any failure, every caller having something to fall back on.
func askBroker(socketPath string) status {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		return status{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := sockutil.Send(conn, map[string]any{
		"op": "status", "version": version.Version}); err != nil {
		return status{}
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		return status{}
	}
	// The status body is itself JSON, carried as the response's output string.
	var response struct {
		Output  string `json:"output"`
		Version string `json:"version"`
		Error   *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return status{}
	}
	// A broker of another release refuses this before it reads the op, so the
	// refusal is the answer: what refused names the build that is running, and
	// there is no status body to read. Reported as skew rather than as a broker
	// that said nothing.
	if response.Error != nil {
		return status{version: response.Version}
	}
	var body struct {
		Configs []string `json:"configs"`
		Version string   `json:"version"`
	}
	if err := json.Unmarshal([]byte(response.Output), &body); err != nil {
		return status{}
	}
	out := status{version: body.Version}
	if len(body.Configs) > 0 {
		// The base config is first by construction.
		out.configDir = filepath.Dir(body.Configs[0])
	}
	return out
}

// unitConfigFile reads the config path out of the broker's unit and its
// drop-ins, or "" when neither is readable or names one: what the broker was
// installed to load, which is the answer left when it is not running. The same
// reader init refuses a config move against.
func unitConfigFile() string {
	return install.UnitConfigFile(brokerUnit)
}

// discoverConfigFile finds the config.toml this host's install uses: the
// running broker's own answer, then the path its unit names. Empty when
// neither answers. The compiled-in default is not a step here, being a guess
// each caller decides for itself.
func discoverConfigFile(st status) string {
	if st.configDir != "" {
		if path := filepath.Join(st.configDir, "config.toml"); exists(path) {
			return path
		}
	}
	return unitConfigFile()
}

// configDirFrom picks the install to act on, given an answer already asked for:
// a flag first, so a host whose install is not the one on this machine can
// still be named, and the compiled-in default last.
//
// The broker's answer is taken as it stands rather than required to hold a
// file, unlike discoverConfigFile: the caller is about to report on the
// directory or remove it, and one that is not there is the finding.
func configDirFrom(explicit string, st status) string {
	if explicit != "" {
		return explicit
	}
	if st.configDir != "" {
		return st.configDir
	}
	if path := unitConfigFile(); path != "" {
		return filepath.Dir(path)
	}
	return install.DefaultConfigDir
}

// resolveConfigDir is configDirFrom for a caller with no other use for the
// broker's answer. The flag is tested here too, so naming one costs no round
// trip.
func resolveConfigDir(explicit, socketPath string) string {
	if explicit != "" {
		return explicit
	}
	return configDirFrom(explicit, askBroker(socketPath))
}

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
	moveConfig    bool
	dryRun        bool
	asJSON        bool

	// The tunables. Each flag's default is the real one, so --help says what a
	// host gets; clearUnset then blanks the ones nobody typed, a value left out
	// meaning "keep what the install has".
	commandEnv           []string
	commandTimeoutSec    int
	commandMaxTimeoutSec int
	commandConcurrency   int
	escalationTimeoutSec int
	secretMinLength      int
	secretMinRefreshSec  int
}

// tunables maps each flag to where it lands, for clearUnset. One table, so a
// flag added to the struct and not here is one that silently reverts the
// install every run.
func (f *initFlags) tunables() map[string]func() {
	return map[string]func(){
		"command-timeout-sec":     func() { f.commandTimeoutSec = 0 },
		"command-max-timeout-sec": func() { f.commandMaxTimeoutSec = 0 },
		"command-concurrency":     func() { f.commandConcurrency = 0 },
		"escalation-timeout-sec":  func() { f.escalationTimeoutSec = 0 },
		"secret-min-length":       func() { f.secretMinLength = 0 },
		"secret-min-refresh-sec":  func() { f.secretMinRefreshSec = 0 },
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
		"account the coding agent runs as (default $SUDO_USER, then you)")
	// One admits a caller to the broker socket and shares the working tree, the
	// other owns the ciphertext; holding one is not holding the other.
	fl.StringVar(&f.clientGroup, "client-group", "",
		"group admitted to the broker socket, and shared with the executor on a working "+
			"tree (default: what the install uses, then "+install.DefaultClientGroup+")")
	fl.StringVar(&f.secretsGroup, "secrets-group", "",
		"group owning the ciphertext in <config-dir>/secrets (default: what the install uses, then the keeper's own group, which is the only account that opens one; naming another adds a second reader)")
	fl.StringVar(&f.brokerUser, "broker-user", "",
		"account that holds the SSH keys and the audit log (default: what the install "+
			"uses, then "+install.DefaultBrokerUser+")")
	fl.StringVar(&f.keeperUser, "keeper-user", "",
		"account that holds the age key (default: what the install uses, then "+
			install.DefaultKeeperUser+")")
	fl.StringVar(&f.execUser, "exec-user", "",
		"account brokered commands run as (default: what the install uses, then "+
			install.DefaultExecUser+")")
	fl.StringVar(&f.configDir, "config-dir", "",
		"where config.toml, the age key and the managed sops files are "+
			"installed (default: ask the broker, then read its unit, then "+install.DefaultConfigDir+")")
	fl.StringVar(&f.sshKey, "ssh-key", "",
		"where the identity the broker lends to brokered commands lives "+
			"(default: what the install uses, then id_ed25519 beside the age key; "+
			"one is minted either way)")
	fl.StringVar(&f.knownHosts, "known-hosts", "",
		"a known_hosts file whose host keys are pinned for the executor, copied to "+
			"<exec-home>/.ssh/known_hosts (default: none, a brokered ssh then verifying "+
			"against /etc/ssh/ssh_known_hosts alone)")
	fl.StringArrayVar(&f.initAgents, "agent", nil,
		"install the deny rules into this agent's own settings, repeatable. "+
			"Default \""+install.AgentAuto+"\": whichever agents the agent account's home "+
			"already carries. A name writes them whether or not the agent is there, "+
			"and composes with auto. Known: "+
			strings.Join(install.KnownAgents(), ", "))
	fl.BoolVar(&f.allowSudo, "allow-sudo", false,
		"let a brokered command ASK to sudo on this host; it cannot sudo on its own. "+
			"The executor gets a password-required sudoers entry pointed at a PAM "+
			"service whose auth step asks the broker, so no password exists anywhere "+
			"and a human approves each command through 'faramir approve'. Off by "+
			"default, and re-running without it takes the grant away")
	fl.StringArrayVar(&f.notifyCommand, "notify-command", nil,
		// The backquoted word is cobra's placeholder for the value, taken from the
		// first one in the string; without it the help reads "stringArray".
		"announce a waiting escalation: one `ARG` each, repeatable, "+
			"--notify-command /usr/bin/wall --notify-command '{prompt}'. \"{prompt}\" "+
			"is the line the broker builds and \"{id}\" the question to answer, and one "+
			"of the two must appear. Keep \"{id}\" off anything that broadcasts: wall "+
			"reaches every terminal on the host and the coding agent has one. The "+
			"program is resolved on PATH here, being run as the account holding every "+
			"decrypted value. Needs --allow-sudo; unset, 'faramir escalations --watch' "+
			"is the only place a question shows up")
	fl.BoolVar(&f.moveConfig, "move-config", false,
		"consent to point this host's daemons at a different --config-dir. There is "+
			"one set of units, so the new directory replaces the old rather than "+
			"standing beside it: the refs the old one served leave the value set and "+
			"stop being redacted, while its age key and ciphertext stay on disk. "+
			"Refused without this")
	fl.BoolVar(&f.dryRun, "dry-run", false, "report what would change and write nothing")
	fl.BoolVar(&f.asJSON, "json", false, "print the report as JSON")
	// The tunables, named for what they bound rather than for the section they
	// land in.
	command, secret := config.DefaultCommand(), config.DefaultSecret()
	fl.StringArrayVar(&f.commandEnv, "command-env", nil,
		"NAME=VALUE in a brokered command's environment; repeatable, and it adds to the built-in table rather than replacing it")
	fl.IntVar(&f.commandTimeoutSec, "command-timeout-sec", command.TimeoutSec,
		"how long a command runs when the request names no timeout")
	fl.IntVar(&f.commandMaxTimeoutSec, "command-max-timeout-sec", command.MaxTimeoutSec,
		"the most a caller may ask for, and the idle bound on a redact stream")
	fl.IntVar(&f.commandConcurrency, "command-concurrency", command.Concurrency,
		"how many brokered commands run at once; the rest are refused busy")
	fl.IntVar(&f.escalationTimeoutSec, "escalation-timeout-sec", config.DefaultEscalationTimeoutSec,
		"how long a sudo question waits for a human before it is refused (1 to 600)")
	fl.IntVar(&f.secretMinLength, "secret-min-length", secret.MinLength,
		"refuse a secret shorter than this: it cannot be redacted without matching inside ordinary words (at least 6)")
	fl.IntVar(&f.secretMinRefreshSec, "secret-min-refresh-sec", secret.MinRefreshSec,
		"the soonest the broker will ask the keeper again whether a managed file changed, at least 1; nothing polls in the background, and linked files are checked every request regardless")
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
			// Refused rather than skipped: `--command-env FOO` reads as setting
			// something, and accepting it would leave the child without it and no
			// reason given.
			return nil, fmt.Errorf("--command-env %q names no value; write it as NAME=VALUE", pair)
		}
		out[name] = value
	}
	return out, nil
}

func runInit(f initFlags) int {

	env, err := namedValues(f.commandEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir init: %v\n", err)
		return 2
	}

	opts := install.Options{
		AgentUser:     operatorName(f.agentUser),
		ClientGroup:   f.clientGroup,
		SecretsGroup:  f.secretsGroup,
		BrokerUser:    f.brokerUser,
		KeeperUser:    f.keeperUser,
		ExecUser:      f.execUser,
		ConfigDir:     resolveConfigDir(f.configDir, socketDefault()),
		SSHKey:        f.sshKey,
		KnownHosts:    f.knownHosts,
		Agents:        f.initAgents,
		AllowSudo:     f.allowSudo,
		NotifyCommand: f.notifyCommand,

		CommandEnv:           env,
		CommandTimeoutSec:    f.commandTimeoutSec,
		CommandMaxTimeoutSec: f.commandMaxTimeoutSec,
		CommandConcurrency:   f.commandConcurrency,
		EscalationTimeoutSec: f.escalationTimeoutSec,
		SecretMinLength:      f.secretMinLength,
		SecretMinRefreshSec:  f.secretMinRefreshSec,
		MoveConfig:           f.moveConfig,
		DryRun:               f.dryRun,
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

// initProjectFlags is one `init-project` run. The tree defaults to the working
// directory, which is safe here and not on init: that one means "provision this
// host" and would otherwise enrol wherever it was run from.
type initProjectFlags struct {
	agentUser   string
	configDir   string
	clientGroup string
	agents      []string
	dryRun      bool
	asJSON      bool
}

func newInitProjectCmd() *cobra.Command {
	var f initProjectFlags
	c := &cobra.Command{
		Use:     "init-project [options] [DIR]",
		Short:   "Enrol one working tree: share it, and configure its agents",
		GroupID: groupProvisioning,
		Args:    atMostOneArg("directory"),
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runInitProject(f, args)) },
	}
	fl := c.Flags()
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account that works in the tree (default $SUDO_USER, then you)")
	fl.StringVar(&f.configDir, "config-dir", "",
		"where the installed config is, which is where the client group is read from "+
			"(default: ask the broker, then read its unit)")
	fl.StringVar(&f.clientGroup, "client-group", "",
		"share the tree with this group instead of the one the installed config "+
			"admits. It overrides that one value: the config still has to load, the "+
			"linked and refused paths in the deny rules an enrolment writes being "+
			"only there")
	fl.StringArrayVar(&f.agents, "agent", nil,
		"coding agent to enrol, repeatable. Default \""+install.AgentAuto+"\": "+
			"whichever agents this tree already carries configuration for. A name "+
			"enrols that agent whether or not it is there, and composes with auto. "+
			"Known: "+strings.Join(install.KnownAgents(), ", "))
	fl.BoolVar(&f.dryRun, "dry-run", false, "report what would change and write nothing")
	fl.BoolVar(&f.asJSON, "json", false, "print the report as JSON")
	return c
}

func runInitProject(f initProjectFlags, args []string) int {

	opts := install.ProjectOptions{
		Dir:         firstArg(args),
		AgentUser:   operatorName(f.agentUser),
		ConfigDir:   resolveConfigDir(f.configDir, socketDefault()),
		ClientGroup: f.clientGroup,
		Agents:      f.agents,
		DryRun:      f.dryRun,
	}
	if !f.asJSON {
		opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
	}

	report, err := install.Project(opts)
	// The failure before the document; see runInit.
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir init-project: %v\n", err)
	}
	if f.asJSON {
		if code := printJSON("init-project", report); code != 0 {
			return code
		}
	}
	if err != nil {
		return 1
	}
	if !f.asJSON {
		for _, warning := range report.Warnings {
			fmt.Fprintf(os.Stderr, "\nWARNING: %s\n", warning)
		}
		fmt.Fprintf(os.Stderr, "\nEnrolled %s with group %s.\n", report.Dir, report.ClientGroup)
		fmt.Fprintln(os.Stderr, "Check it from the tree: cd there and run "+
			"`faramir run -- pwd`. A brokered command runs where its caller was, "+
			"so that is the whole test.")
		if report.DryRun {
			fmt.Fprintln(os.Stderr, "\nDry run: nothing was written.")
		}
	}
	return 0
}

type doctorFlags struct {
	configDir    string
	agentUser    string
	clientGroup  string
	secretsGroup string
	brokerUser   string
	keeperUser   string
	execUser     string
	asJSON       bool
	when         string
}

func newDoctorCmd() *cobra.Command {
	var f doctorFlags
	c := &cobra.Command{
		Use:     "doctor [options]",
		Short:   "Report whether the install is doing its job",
		GroupID: groupProvisioning,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runDoctor(f)) },
	}
	fl := c.Flags()
	fl.StringVar(&f.configDir, "config-dir", "", "where config.toml was installed (default: ask the broker)")
	fl.StringVar(&f.agentUser, "agent-user", "", "account the coding agent runs as")
	// Empty rather than the install defaults: doctor reads what this host runs
	// out of the units, the config and the secrets directory, and a default here
	// would answer about accounts a host installed with other names does not
	// have. Each is an override for a host whose install is not this one.
	fl.StringVar(&f.clientGroup, "client-group", "",
		"override the group admitted to the broker socket, instead of reading [server] allowed_group")
	fl.StringVar(&f.secretsGroup, "secrets-group", "",
		"override the group owning the ciphertext, instead of reading it off <config-dir>/secrets")
	fl.StringVar(&f.brokerUser, "broker-user", "",
		"override the account the broker runs as, instead of reading faramir-broker.service")
	fl.StringVar(&f.keeperUser, "keeper-user", "",
		"override the account that holds the age key, instead of reading faramir-keeper.service")
	fl.StringVar(&f.execUser, "exec-user", "",
		"override the account brokered commands run as, instead of reading faramir-exec.service")
	fl.BoolVar(&f.asJSON, "json", false, "print the findings as JSON")
	addColorFlag(c, &f.when)
	return c
}

func runDoctor(f doctorFlags) int {

	paint, err := newPalette(f.when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir doctor: %v\n", err)
		return 2
	}
	// Before the round trip below, which changes what it would report: opening
	// the broker socket activates the service, and that starts the keeper and
	// executor sockets it Requires=.
	sockets := install.SampleSockets()
	// One round trip: the same answer decides which install this is and whether
	// the daemons are running the code that was installed.
	broker := askBroker(socketDefault())
	report := install.Diagnose(install.DoctorOptions{
		ConfigDir:     configDirFrom(f.configDir, broker),
		BrokerVersion: broker.version,
		SocketStates:  sockets,
		AgentUser:     operatorName(f.agentUser),
		ClientGroup:   f.clientGroup,
		BrokerUser:    f.brokerUser,
		KeeperUser:    f.keeperUser,
		ExecUser:      f.execUser,
		SecretsGroup:  f.secretsGroup,
	})
	if f.asJSON {
		if code := printJSON("doctor", report); code != 0 {
			return code
		}
	} else {
		printDiagnosis(os.Stdout, paint, report)
	}
	if report.Failed {
		return 1
	}
	return 0
}

// printDiagnosis lays the findings out as status, check, detail. The check is
// named once per run of findings that share it, and the detail wraps under
// itself rather than being cut at the terminal edge.
func printDiagnosis(w io.Writer, paint palette, report install.DoctorReport) {
	statusWidth := columns(statusColumn(install.StatusFailed)) // the longest
	name := 0
	for _, finding := range report.Findings {
		name = max(name, len(finding.Name))
	}
	indent := statusWidth + 2 + name + 2
	counts := map[install.Status]int{}
	previous := ""
	for _, finding := range report.Findings {
		counts[finding.Status]++
		label := finding.Name
		if label == previous {
			label = ""
		}
		previous = finding.Name
		// A finding with no detail is still a line.
		first, rest := "", []string(nil)
		if lines := wrapText(finding.Detail, terminalWidth()-indent); len(lines) > 0 {
			first, rest = lines[0], lines[1:]
		}
		_, _ = fmt.Fprintf(w, "%s  %-*s  %s\n", paintStatus(paint, finding.Status), name, label, first)
		for _, line := range rest {
			_, _ = fmt.Fprintf(w, "%*s%s\n", indent, "", line)
		}
	}
	if len(report.Findings) == 0 {
		return
	}
	var totals []string
	for _, status := range []install.Status{install.StatusOK, install.StatusNA,
		install.StatusWarn, install.StatusFailed} {
		if counts[status] > 0 {
			totals = append(totals, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", paint.bold(strings.Join(totals, ", ")))
	printNotAsked(w, paint, report.NotAsked)
}

// printNotAsked says how much of the examination did not happen, outside the
// findings and the totals: a skipped check is one warn line whatever it stood
// for, so the totals alone read the same on a host barely examined.
func printNotAsked(w io.Writer, paint palette, count int) {
	if count == 0 {
		return
	}
	note := fmt.Sprintf("%d more check(s) were not made, so the totals above are not "+
		"the whole examination.", count)
	if os.Geteuid() != 0 {
		note += " Each of them has to read a file or run a command as an account that " +
			"is not yours: re-run as `sudo faramir doctor`."
	}
	_, _ = fmt.Fprintln(w)
	for _, line := range wrapText(note, terminalWidth()) {
		_, _ = fmt.Fprintf(w, "%s\n", paint.warn(line))
	}
}

// statusColumn is the glyph and the word: the glyph makes the column scannable,
// the word survives a pipe into a log or a grep for "failed". The glyph is
// dropped where the locale is not UTF-8.
func statusColumn(status install.Status) string {
	mark := map[install.Status]string{
		install.StatusOK:     "✓", // check mark
		install.StatusNA:     "·", // middle dot: neither asserted nor withheld
		install.StatusWarn:   "!",
		install.StatusFailed: "✗", // ballot X
	}[status]
	if mark == "" || !unicodeLocale() {
		return fmt.Sprintf("%-6s", status)
	}
	return fmt.Sprintf("%s %-6s", mark, status)
}

// columns is a string's width on screen. Every glyph above is one column wide,
// so runes are the answer and len would count a check mark as three.
func columns(text string) int { return utf8.RuneCountInString(text) }

// unicodeLocale reports whether the terminal was told to expect UTF-8, in the
// order the C library reads these.
func unicodeLocale() bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(name); value != "" {
			return strings.Contains(strings.ToUpper(value), "UTF-8") ||
				strings.Contains(strings.ToUpper(value), "UTF8")
		}
	}
	return false
}

func paintStatus(paint palette, status install.Status) string {
	text := statusColumn(status)
	switch status {
	case install.StatusOK:
		return paint.ok(text)
	// Dim rather than a colour of its own: nothing was claimed, so the line is
	// there to be read past.
	case install.StatusNA:
		return paint.dim(text)
	case install.StatusWarn:
		return paint.warn(text)
	case install.StatusFailed:
		return paint.bad(text)
	default:
		// A status this build does not know is the one worth looking at.
		return paint.bad(text)
	}
}

// wrapText breaks a detail into lines that fit. Words only, so a path stays
// copyable: an over-long word overflows rather than being cut.
func wrapText(text string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	line := ""
	for word := range strings.FieldsSeq(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// terminalWidth is $COLUMNS, then 80. A wrong guess costs a wrapped line, so
// this needs no dependency.
func terminalWidth() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 40 {
		return columns
	}
	return 80
}

type uninstallFlags struct {
	configDir string
}

func newUninstallCmd() *cobra.Command {
	var f uninstallFlags
	c := &cobra.Command{
		Use:     "uninstall [options]",
		Short:   "Remove the broker, keeping the key, the secrets directory and the log",
		GroupID: groupProvisioning,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runUninstall(f)) },
	}
	c.Flags().StringVar(&f.configDir, "config-dir", "",
		"where config.toml was installed (default: ask the broker, then read its unit)")
	return c
}

func runUninstall(f uninstallFlags) int {

	if !requireRoot("uninstall", "it removes the units and the installed files") {
		return 1
	}
	left, err := install.Uninstall(resolveConfigDir(f.configDir, socketDefault()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir uninstall: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nLeft in place on purpose:")
	for _, item := range left {
		fmt.Fprintf(os.Stderr, "  %s\n", item)
	}
	fmt.Fprintln(os.Stderr, "\nRemove those by hand if you really mean to. Deleting the age "+
		"key makes every managed sops file unreadable, retroactively.")
	return 0
}

func newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "reload",
		Short:   "Drop the daemons onto a changed configuration",
		GroupID: groupProvisioning,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runReload()) },
	}
}

func runReload() int {

	if !requireRoot("reload", "it restarts the daemons") {
		return 1
	}
	if err := install.Reload(); err != nil {
		fmt.Fprintf(os.Stderr, "faramir reload: %v\n", err)
		return 1
	}
	return 0
}
