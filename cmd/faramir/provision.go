package main

// The subcommands that provision and inspect a host.  All local; none opens the
// broker socket except through the checks init runs at the end.

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

// resolveConfigDir decides which install doctor is examining.  The compiled-in
// default is only right for a host that took it, so the broker is asked over
// the socket; a broker that does not answer is itself the finding, and the
// default is then all there is to look at.
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
// on any failure, leaving doctor to carry on against the default.
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
	// The base config is first by construction; the rest are its drop-ins.
	return filepath.Dir(body.Configs[0])
}

func cmdInit(args []string) int {
	fs := newFlagSet("init", "init [options]")
	operator := fs.String("operator", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
	// One admits a caller to the broker socket and shares the working tree, the
	// other owns the ciphertext; holding one is not holding the other.
	clientGroup := fs.String("client-group", install.DefaultGroup,
		"group admitted to the broker socket, and shared with the executor on a working tree")
	storeGroup := fs.String("store-group", "",
		"group owning the managed sops files (default: the keeper's own, which is the only account that opens one)")
	brokerUser := fs.String("broker-user", install.DefaultBrokerUser, "account that holds the SSH keys and the audit log")
	keeperUser := fs.String("keeper-user", install.DefaultKeeperUser, "account that holds the age key")
	execUser := fs.String("exec-user", install.DefaultExecUser, "account brokered commands run as")
	configDir := fs.String("config-dir", install.DefaultConfigDir,
		"where config.toml, config.d/, the age key and the managed sops files are installed")
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
		Operator:      operatorName(*operator),
		Group:         *clientGroup,
		StoreGroup:    *storeGroup,
		BrokerUser:    *brokerUser,
		KeeperUser:    *keeperUser,
		ExecUser:      *execUser,
		ConfigDir:     *configDir,
		AgeRecipients: recipients,
		SSHKey:        *sshKey,
		Agents:        initAgents,
		DryRun:        *dryRun,
	}
	// Progress goes to stderr so --json owns stdout, and is suppressed under
	// --json entirely.
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

// cmdInitProject enrols one tree, defaulting to the working directory.  Safe
// here and not on init, which means "provision this host" and would otherwise
// enrol wherever it was run from.
func cmdInitProject(args []string) int {
	fs := newFlagSet("init-project", "init-project [options] [DIR]")
	operator := fs.String("operator", "",
		"account that works in the tree (default $SUDO_USER, then you)")
	configDir := fs.String("config-dir", install.DefaultConfigDir,
		"where the installed config is, which is where the client group is read from")
	clientGroup := fs.String("client-group", "",
		"override the client group instead of reading it from the installed config")
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
		Group:     *clientGroup,
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
	clientGroup := fs.String("client-group", install.DefaultGroup,
		"group admitted to the broker socket")
	storeGroup := fs.String("store-group", "",
		"group owning the managed sops files (default: the keeper's own)")
	brokerUser := fs.String("broker-user", install.DefaultBrokerUser,
		"account the broker runs as, which --check has to be asked as")
	keeperUser := fs.String("keeper-user", install.DefaultKeeperUser, "account that holds the age key")
	execUser := fs.String("exec-user", install.DefaultExecUser, "account brokered commands run as")
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
		Group:      *clientGroup,
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
	for _, status := range []install.Status{install.StatusOK, install.StatusWarn, install.StatusFailed} {
		if counts[status] > 0 {
			totals = append(totals, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", paint.bold(strings.Join(totals, ", ")))
}

// statusColumn is the glyph and the word: the glyph makes the column scannable,
// the word survives a pipe into a log or a grep for "failed".  The glyph is
// dropped where the locale is not UTF-8.
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
