package main

// The subcommands that provision and inspect a host.  They act on files rather
// than through the broker, but they ask a running one where the install is: see
// askBroker.  init also runs its own checks through it at the end.

import (
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

	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/sockutil"
)

// brokerUnit records the config the daemons loaded.  A variable so a test can
// point it at a fixture, and taken from install rather than written out again:
// init refuses a config move against the same file, so a second literal here
// would drift from the one the refusal reads.
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
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return status{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := sockutil.Send(conn, map[string]any{"op": "status"}); err != nil {
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
		Output string `json:"output"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return status{}
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
		// The base config is first by construction; the rest are its drop-ins.
		out.configDir = filepath.Dir(body.Configs[0])
	}
	return out
}

// unitConfigFile reads the config path out of the broker's unit and its
// drop-ins, or "" when neither is readable or names one.  What the broker was
// installed to load, which is the answer left when the broker itself is not
// running.
//
// The same reader init refuses a config move against, so what this resolves and
// what that compares it to cannot disagree.
func unitConfigFile() string {
	return install.UnitConfigFile(brokerUnit)
}

// discoverConfigFile finds the config.toml this host's install uses: the
// running broker's own answer, then the path its unit names.  Empty when
// neither answers, which is a host with no install rather than one whose
// install moved.  The compiled-in default is not a step here, being a guess
// each caller decides for itself.
func discoverConfigFile(st status) string {
	if st.configDir != "" {
		if path := filepath.Join(st.configDir, "config.toml"); exists(path) {
			return path
		}
	}
	return unitConfigFile()
}

// configDirFrom picks the install to act on, given an answer already asked
// for: a flag first, so a host whose install is not the one on this machine can
// still be named, and the compiled-in default last.
//
// The broker's answer is taken as it stands rather than required to hold a
// file, which is where this differs from discoverConfigFile: the caller is
// about to report on the directory or remove it, and one that is not there is
// the finding.
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
// broker's answer.  The flag is tested here as well, so naming one costs no
// round trip.
func resolveConfigDir(explicit, socketPath string) string {
	if explicit != "" {
		return explicit
	}
	return configDirFrom(explicit, askBroker(socketPath))
}

func cmdInit(args []string) int {
	fs := newFlagSet("init", "init [options]")
	operatorUser := fs.String("operator-user", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
	// One admits a caller to the broker socket and shares the working tree, the
	// other owns the ciphertext; holding one is not holding the other.
	clientGroup := fs.String("client-group", "",
		"group admitted to the broker socket, and shared with the executor on a working "+
			"tree (default: what the install uses, then "+install.DefaultClientGroup+")")
	secretsGroup := fs.String("secrets-group", "",
		"group owning the ciphertext in <config-dir>/secrets (default: what the install uses, then the keeper's own group, which is the only account that opens one; naming another adds a second reader)")
	brokerUser := fs.String("broker-user", "",
		"account that holds the SSH keys and the audit log (default: what the install "+
			"uses, then "+install.DefaultBrokerUser+")")
	keeperUser := fs.String("keeper-user", "",
		"account that holds the age key (default: what the install uses, then "+
			install.DefaultKeeperUser+")")
	execUser := fs.String("exec-user", "",
		"account brokered commands run as (default: what the install uses, then "+
			install.DefaultExecUser+")")
	configDir := fs.String("config-dir", "",
		"where config.toml, config.d/, the age key and the managed sops files are "+
			"installed (default: ask the broker, then read its unit, then "+install.DefaultConfigDir+")")
	socket := fs.String("socket", socketDefault(), "broker socket path ($FARAMIR_SOCKET)")
	sshKey := fs.String("ssh-key", "",
		"where the identity the broker lends to brokered commands lives "+
			"(default: what the install uses, then id_ed25519 beside the age key; "+
			"one is minted either way)")
	knownHosts := fs.String("known-hosts", "",
		"a known_hosts file whose host keys are pinned for the executor, copied to "+
			"<exec-home>/.ssh/known_hosts (default: none, a brokered ssh then verifying "+
			"against /etc/ssh/ssh_known_hosts alone)")
	var initAgents multiFlag
	fs.Var(&initAgents, "agent",
		"install the deny rules into this agent's own settings, repeatable "+
			"(none by default; known: "+strings.Join(install.KnownAgents(), ", ")+")")
	allowSudo := fs.Bool("allow-sudo", false,
		"let a brokered command ASK to sudo on this host; it cannot sudo on its own. "+
			"The executor gets a password-required sudoers entry pointed at a PAM "+
			"service whose auth step asks the broker, so no password exists anywhere "+
			"and a human approves each command through 'faramir approve'. Off by "+
			"default, and re-running without it takes the grant away")
	moveConfig := fs.Bool("move-config", false,
		"consent to point this host's daemons at a different --config-dir. There is "+
			"one set of units, so the new directory replaces the old rather than "+
			"standing beside it: the refs the old one served leave the value set and "+
			"stop being redacted, while its age key and ciphertext stay on disk. "+
			"Refused without this")
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var recipients multiFlag
	fs.Var(&recipients, "age-recipient",
		"an age PUBLIC key that may also decrypt the secrets directory, added to .sops.yaml beside the keeper's own so a backup of the ciphertext opens without the keeper's key; repeatable, and only read at the install that creates the file")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	opts := install.Options{
		OperatorUser:  operatorName(*operatorUser),
		ClientGroup:   *clientGroup,
		SecretsGroup:  *secretsGroup,
		BrokerUser:    *brokerUser,
		KeeperUser:    *keeperUser,
		ExecUser:      *execUser,
		ConfigDir:     resolveConfigDir(*configDir, *socket),
		AgeRecipients: recipients,
		SSHKey:        *sshKey,
		KnownHosts:    *knownHosts,
		Agents:        initAgents,
		AllowSudo:     *allowSudo,
		MoveConfig:    *moveConfig,
		DryRun:        *dryRun,
	}
	// Progress goes to stderr so --json owns stdout, and is suppressed under
	// --json entirely.
	if !*asJSON {
		opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
		// Named before anything is written.  Without --config-dir this was
		// discovered, and an install written somewhere the operator did not expect
		// is a second install rather than an error: new keys, an empty secrets
		// directory, and the units pointed at it.
		fmt.Fprintf(os.Stderr, "provisioning the install at %s\n", opts.ConfigDir)
	}

	report, err := install.Run(opts)
	if *asJSON {
		body, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr == nil {
			fmt.Println(string(body))
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	if !*asJSON {
		reportToOperator(report)
	}
	return 0
}

// reportToOperator prints what a person needs after a run: what installs
// cleanly and then does not work, and the public key the fleet must authorize.
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

// cmdInitProject enrols one tree, defaulting to the working directory.  Safe
// here and not on init, which means "provision this host" and would otherwise
// enrol wherever it was run from.
func cmdInitProject(args []string) int {
	fs := newFlagSet("init-project", "init-project [options] [DIR]")
	operatorUser := fs.String("operator-user", "",
		"account that works in the tree (default $SUDO_USER, then you)")
	configDir := fs.String("config-dir", "",
		"where the installed config is, which is where the client group is read from "+
			"(default: ask the broker, then read its unit)")
	socket := fs.String("socket", socketDefault(), "broker socket path ($FARAMIR_SOCKET)")
	clientGroup := fs.String("client-group", "",
		"override the client group instead of reading it from the installed config")
	hook := fs.Bool("hook", true,
		"register the PreToolUse hook, which redacts this project's command output. "+
			"On Claude Code that auto-approves Bash here as a consequence; the other "+
			"agents have no approval to give, so it costs them nothing")
	var agents multiFlag
	fs.Var(&agents, "agent",
		"coding agent to enrol, repeatable (default claude; known: "+
			strings.Join(install.KnownAgents(), ", ")+")")
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "faramir: init-project takes one directory")
		return 2
	}

	opts := install.ProjectOptions{
		Dir:          fs.Arg(0),
		OperatorUser: operatorName(*operatorUser),
		ConfigDir:    resolveConfigDir(*configDir, *socket),
		ClientGroup:  *clientGroup,
		Hook:         *hook,
		Agents:       agents,
		DryRun:       *dryRun,
	}
	if !*asJSON {
		opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
	}

	report, err := install.Project(opts)
	if *asJSON {
		body, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr == nil {
			fmt.Println(string(body))
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	if !*asJSON {
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

func cmdDoctor(args []string) int {
	fs := newFlagSet("doctor", "doctor [options]")
	configDir := fs.String("config-dir", "", "where config.toml was installed (default: ask the broker)")
	socket := fs.String("socket", socketDefault(), "broker socket path ($FARAMIR_SOCKET)")
	operatorUser := fs.String("operator-user", "", "account the coding agent runs as")
	// Empty rather than the install defaults: doctor reads what this host
	// actually runs out of the units, the config and the secrets directory, and
	// a default here would shadow that and answer about accounts a host
	// installed with other names does not have.  Each names an override for a
	// host whose install is not the one on this machine.
	clientGroup := fs.String("client-group", "",
		"override the group admitted to the broker socket, instead of reading [server] allowed_group")
	secretsGroup := fs.String("secrets-group", "",
		"override the group owning the ciphertext, instead of reading it off <config-dir>/secrets")
	brokerUser := fs.String("broker-user", "",
		"override the account the broker runs as, instead of reading faramir-broker.service")
	keeperUser := fs.String("keeper-user", "",
		"override the account that holds the age key, instead of reading faramir-keeper.service")
	execUser := fs.String("exec-user", "",
		"override the account brokered commands run as, instead of reading faramir-exec.service")
	asJSON := fs.Bool("json", false, "print the findings as JSON")
	when := fs.String("color", "auto", "colourise: auto, always or never")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	paint, err := newPalette(*when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	// Before the round trip below, which changes what it would report: opening
	// the broker socket activates the service, and that starts the keeper and
	// executor sockets it Requires=.  Sampled here, a socket that was down is
	// still down in the finding.
	sockets := install.SampleSockets()
	// One round trip: the same answer decides which install this is and whether
	// the daemons are running the code that was installed.
	broker := askBroker(*socket)
	report := install.Diagnose(install.DoctorOptions{
		ConfigDir:     configDirFrom(*configDir, broker),
		BrokerVersion: broker.version,
		SocketStates:  sockets,
		OperatorUser:  operatorName(*operatorUser),
		ClientGroup:   *clientGroup,
		BrokerUser:    *brokerUser,
		KeeperUser:    *keeperUser,
		ExecUser:      *execUser,
		SecretsGroup:  *secretsGroup,
	})
	if *asJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
			return 1
		}
		fmt.Println(string(body))
	} else {
		printDiagnosis(os.Stdout, paint, report)
	}
	if report.Failed {
		return 1
	}
	return 0
}

// printDiagnosis lays the findings out as status, check, detail.  The check is
// named once per run of findings that share it, so three sockets read as one
// check with three answers, and the detail wraps under itself rather than being
// cut at the terminal edge.
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
// findings and outside the totals.  A check that was skipped is one warn line
// whatever it stood for, so the totals read the same on a host examined in full
// and on one where a dozen questions were never put.
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
// the word survives a pipe into a log or a grep for "failed".  The glyph is
// dropped where the locale is not UTF-8.
func statusColumn(status install.Status) string {
	mark := map[install.Status]string{
		install.StatusOK:     "✓", // check mark
		install.StatusNA:     "–", // en dash: neither asserted nor withheld
		install.StatusWarn:   "!",
		install.StatusFailed: "✗", // ballot X
	}[status]
	if mark == "" || !unicodeLocale() {
		return fmt.Sprintf("%-6s", status)
	}
	return fmt.Sprintf("%s %-6s", mark, status)
}

// columns is a string's width on screen.  Every glyph above is one column wide,
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
	// there to be read past by someone scanning for the one that is not ok.
	case install.StatusNA:
		return paint.dim(text)
	case install.StatusWarn:
		return paint.warn(text)
	default:
		return paint.bad(text)
	}
}

// wrapText breaks a detail into lines that fit.  Words only, so a path stays
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

// terminalWidth is $COLUMNS, then 80.  A wrong guess costs a wrapped line, so
// this needs no dependency.
func terminalWidth() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 40 {
		return columns
	}
	return 80
}

func cmdUninstall(args []string) int {
	fs := newFlagSet("uninstall", "uninstall [options]")
	configDir := fs.String("config-dir", "",
		"where config.toml was installed (default: ask the broker, then read its unit)")
	socket := fs.String("socket", socketDefault(), "broker socket path ($FARAMIR_SOCKET)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir: uninstall must run as root")
		return 1
	}
	left, err := install.Uninstall(resolveConfigDir(*configDir, *socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
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

func cmdReload(args []string) int {
	fs := newFlagSet("reload", "reload")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir: reload must run as root: it stops the units")
		return 1
	}
	if err := install.Reload(); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	return 0
}
