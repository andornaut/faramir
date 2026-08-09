package main

// The subcommands that provision and inspect a host, as against the ones that
// talk to a running broker.  All of them are local; none opens the broker
// socket except through the checks init runs at the end.

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

// resolveConfigDir decides which install doctor is examining.
//
// The compiled-in default is only right for a host that took it.  Anywhere else
// doctor would report the config missing and every check that reads it as
// broken, on a host that is working: the one thing that knows where the config
// actually is, without being told, is the broker reading it.
//
// Asked over the socket rather than read from the unit, because a broker
// answering at all is what makes the answer worth having.  Falling back to the
// default when it does not answer is not a guess about the path so much as the
// only thing left to look at, and a broker that is down is itself the finding.
func resolveConfigDir(explicit, socketPath string) string {
	if explicit != "" {
		return explicit
	}
	if dir := brokerConfigDir(socketPath); dir != "" {
		return dir
	}
	return install.DefaultConfigDir
}

// brokerConfigDir asks a running broker which config it loaded, or returns ""
// when there is nothing listening or it answers with something unexpected.
// Every failure is the same answer: doctor carries on against the default and
// reports what it finds there.
func brokerConfigDir(socketPath string) string {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := sockutil.Send(conn, map[string]any{"op": "status"}); err != nil {
		return ""
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		return ""
	}
	// The status body is itself JSON, carried as the response's output string.
	var response struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return ""
	}
	var body struct {
		Configs []string `json:"configs"`
	}
	if err := json.Unmarshal([]byte(response.Output), &body); err != nil || len(body.Configs) == 0 {
		return ""
	}
	// The base config is first by construction; the rest are its drop-ins,
	// which sit in a subdirectory of the same place.
	return filepath.Dir(body.Configs[0])
}

func cmdInit(args []string) int {
	fs := newFlagSet("init", "init [options]")
	operator := fs.String("operator", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
	group := fs.String("group", install.DefaultGroup,
		"shared group giving the service accounts access to a tree brokered commands run in")
	storeGroup := fs.String("store-group", "",
		"group owning the managed sops files (default: the keeper's own group, which is the only account that opens one)")
	brokerUser := fs.String("broker-user", install.DefaultBrokerUser, "account that holds the SSH keys and the audit log")
	keeperUser := fs.String("keeper-user", install.DefaultKeeperUser, "account that holds the age key")
	execUser := fs.String("exec-user", install.DefaultExecUser, "account brokered commands run as")
	configDir := fs.String("config-dir", install.DefaultConfigDir,
		"where config.toml, config.d/, the age key and the managed sops files are installed")
	operatorAgeKey := fs.String("operator-age-key", "",
		"mint an age identity here and list it alongside the keeper's, so the operator can read the files they own")
	sshKey := fs.String("ssh-key", "",
		"identity the broker lends to brokered commands, generated when missing")
	var initAgents multiFlag
	fs.Var(&initAgents, "agent",
		"install the deny rules into this agent's own settings, repeatable "+
			"(none by default; known: "+strings.Join(install.KnownAgents(), ", ")+")")
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var recipients multiFlag
	fs.Var(&recipients, "age-recipient", "extra age recipient for .sops.yaml (repeatable)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	opts := install.Options{
		Operator:       operatorName(*operator),
		Group:          *group,
		StoreGroup:     *storeGroup,
		BrokerUser:     *brokerUser,
		KeeperUser:     *keeperUser,
		ExecUser:       *execUser,
		ConfigDir:      *configDir,
		AgeRecipients:  recipients,
		OperatorAgeKey: *operatorAgeKey,
		SSHKey:         *sshKey,
		Agents:         initAgents,
		DryRun:         *dryRun,
	}
	// Progress goes to stderr so --json owns stdout, and is suppressed under
	// --json entirely: a caller asking for the report does not want the prose.
	if !*asJSON {
		opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
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

// reportToOperator prints what a person needs after a run: the things that
// install cleanly and then do not work, and the public key the fleet has to
// authorize before any of it reaches a managed host.
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

// cmdInitProject enrols one tree.
//
// The directory defaults to the working one, which is safe here and is not on
// init: this command means "enrol this project", so where you are standing is
// the answer, where init means "provision this host" and would enrol whatever
// directory it happened to be run from.
func cmdInitProject(args []string) int {
	fs := newFlagSet("init-project", "init-project [options] [DIR]")
	operator := fs.String("operator", "",
		"account that works in the tree (default $SUDO_USER, then you)")
	configDir := fs.String("config-dir", install.DefaultConfigDir,
		"where the installed config is, which is where the shared group is read from")
	group := fs.String("group", "",
		"override the shared group instead of reading it from the installed config")
	hook := fs.Bool("hook", true,
		"register the PreToolUse hook, which redacts this project's command output "+
			"and auto-approves Bash here as a consequence")
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
		Dir:       fs.Arg(0),
		Operator:  operatorName(*operator),
		ConfigDir: *configDir,
		Group:     *group,
		Hook:      *hook,
		Agents:    agents,
		DryRun:    *dryRun,
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
		fmt.Fprintf(os.Stderr, "\nEnrolled %s with group %s.\n", report.Dir, report.Group)
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
	operator := fs.String("operator", "", "account the coding agent runs as")
	group := fs.String("group", install.DefaultGroup, "shared group")
	brokerUser := fs.String("broker-user", install.DefaultBrokerUser,
		"account the broker runs as, which --check has to be asked as")
	keeperUser := fs.String("keeper-user", install.DefaultKeeperUser, "account that holds the age key")
	execUser := fs.String("exec-user", install.DefaultExecUser, "account brokered commands run as")
	storeGroup := fs.String("store-group", "",
		"group owning the managed sops files (default: the keeper's own)")
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
	report := install.Diagnose(install.DoctorOptions{
		ConfigDir:  resolveConfigDir(*configDir, *socket),
		Operator:   operatorName(*operator),
		Group:      *group,
		BrokerUser: *brokerUser,
		KeeperUser: *keeperUser,
		ExecUser:   *execUser,
		StoreGroup: *storeGroup,
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

// printDiagnosis lays the findings out as a table: status, check, detail.
//
// The check is named once per run of findings that share it, so three sockets
// read as one check with three answers rather than as three checks that happen
// to have the same name.  The detail wraps under itself: these are sentences
// naming an account and a path, and one cut off at the terminal edge is one
// nobody acts on.
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
		// A finding with no detail is still a line: the status and the name are
		// the finding, and the detail is what one has to say for itself.
		first, rest := "", []string(nil)
		if lines := wrapText(finding.Detail, terminalWidth()-indent); len(lines) > 0 {
			first, rest = lines[0], lines[1:]
		}
		fmt.Fprintf(w, "%s  %-*s  %s\n", paintStatus(paint, finding.Status), name, label, first)
		for _, line := range rest {
			fmt.Fprintf(w, "%*s%s\n", indent, "", line)
		}
	}
	if len(report.Findings) == 0 {
		return
	}
	var totals []string
	for _, status := range []install.Status{install.StatusOK, install.StatusWarn, install.StatusFailed} {
		if counts[status] > 0 {
			totals = append(totals, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	fmt.Fprintf(w, "\n%s\n", paint.bold(strings.Join(totals, ", ")))
}

// statusColumn is the glyph and the word, which is what an eye finds before it
// reads anything: a column of ticks with the one cross in it standing out.
//
// Both, not one: the glyph is what makes the column scannable, and the word is
// what survives a pipe into a log or a grep for "failed".  The glyph is dropped
// where the locale is not UTF-8, rather than printing a replacement character
// against every finding.
func statusColumn(status install.Status) string {
	mark := map[install.Status]string{
		install.StatusOK:     "✓", // check mark
		install.StatusWarn:   "!",
		install.StatusFailed: "✗", // ballot X
	}[status]
	if mark == "" || !unicodeLocale() {
		return fmt.Sprintf("%-6s", status)
	}
	return fmt.Sprintf("%s %-6s", mark, status)
}

// columns is a string's width on screen.  Every glyph above is one column wide,
// so counting runes is the same answer without a width table, and len would
// count a check mark as three.
func columns(text string) int { return utf8.RuneCountInString(text) }

// unicodeLocale reports whether the terminal was told to expect UTF-8.  The
// first of these that is set decides, which is the order the C library reads
// them in.
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
	case install.StatusWarn:
		return paint.warn(text)
	default:
		return paint.bad(text)
	}
}

// wrapText breaks a detail into lines that fit.  Words only: a path is one, and
// splitting one mid-word makes it uncopyable, so an over-long word takes a line
// of its own and overflows rather than being cut.
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

// terminalWidth is $COLUMNS, then 80.  No dependency for this: the module links
// golang.org/x/term only indirectly, and a wrong guess costs a wrapped line.
func terminalWidth() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 40 {
		return columns
	}
	return 80
}

func cmdUninstall(args []string) int {
	fs := newFlagSet("uninstall", "uninstall [options]")
	configDir := fs.String("config-dir", install.DefaultConfigDir, "where config.toml was installed")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir: uninstall must run as root")
		return 1
	}
	left, err := install.Uninstall(*configDir)
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
