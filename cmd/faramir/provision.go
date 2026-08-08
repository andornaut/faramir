package main

// The subcommands that provision and inspect a host, as against the ones that
// talk to a running broker.  All of them are local; none opens the broker
// socket except through the checks init runs at the end.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

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
		"account the coding agent runs as (default $OPERATOR, then $SUDO_USER)")
	group := fs.String("group", install.DefaultGroup,
		"shared group giving the service accounts access to a tree brokered commands run in")
	brokerUser := fs.String("broker-user", install.DefaultBrokerUser, "account that holds the SSH keys and the audit log")
	keeperUser := fs.String("keeper-user", install.DefaultKeeperUser, "account that holds the age key")
	execUser := fs.String("exec-user", install.DefaultExecUser, "account brokered commands run as")
	configDir := fs.String("config-dir", install.DefaultConfigDir, "where config.toml and config.d/ are installed")
	secretsDir := fs.String("secrets-dir", "", "where the managed sops files live (default CONFIG_DIR/secrets)")
	binaries := fs.String("binaries", "",
		"directory holding the built binaries (default: the directory this one is in)")
	operatorAgeKey := fs.String("operator-age-key", "",
		"mint an age identity here and list it alongside the keeper's, so the operator can read the files they own")
	sshKey := fs.String("ssh-key", "",
		"identity the broker lends to brokered commands, generated when missing")
	sealAgeKey := fs.Bool("seal-age-key", false, "seal the age key to this host's TPM")
	removePlaintext := fs.Bool("remove-plaintext-age-key", false,
		"delete the plaintext age key once the sealed one is proven to work (irreversible)")
	agentConfig := fs.Bool("agent-config", false,
		"install the Read deny rules into the operator's Claude settings")
	overwriteConfig := fs.Bool("overwrite-config", false,
		"replace an installed config.toml instead of keeping it (destructive)")
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var recipients multiFlag
	fs.Var(&recipients, "age-recipient", "extra age recipient for .sops.yaml (repeatable)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	opts := install.Options{
		Operator:              operatorName(*operator),
		Group:                 *group,
		BrokerUser:            *brokerUser,
		KeeperUser:            *keeperUser,
		ExecUser:              *execUser,
		ConfigDir:             *configDir,
		SecretsDir:            *secretsDir,
		Binaries:              *binaries,
		AgeRecipients:         recipients,
		OperatorAgeKey:        *operatorAgeKey,
		SSHKey:                *sshKey,
		SealAgeKey:            *sealAgeKey,
		RemovePlaintextAgeKey: *removePlaintext,
		AgentConfig:           *agentConfig,
		OverwriteConfig:       *overwriteConfig,
		DryRun:                *dryRun,
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
		"account that works in the tree (default $OPERATOR, then $SUDO_USER)")
	configDir := fs.String("config-dir", install.DefaultConfigDir,
		"where the installed config is, which is where the shared group is read from")
	group := fs.String("group", "",
		"override the shared group instead of reading it from the installed config")
	hook := fs.Bool("hook", true,
		"register the PreToolUse hook, which redacts this project's command output "+
			"and auto-approves Bash here as a consequence")
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
	asJSON := fs.Bool("json", false, "print the findings as JSON")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	report := install.Diagnose(install.DoctorOptions{
		ConfigDir:  resolveConfigDir(*configDir, *socket),
		Operator:   operatorName(*operator),
		Group:      *group,
		BrokerUser: *brokerUser,
		KeeperUser: *keeperUser,
		ExecUser:   *execUser,
	})
	if *asJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
			return 1
		}
		fmt.Println(string(body))
	} else {
		for _, finding := range report.Findings {
			fmt.Printf("%-8s %s\n", finding.Status, finding.Name)
			if finding.Detail != "" {
				fmt.Printf("         %s\n", finding.Detail)
			}
		}
	}
	if report.Failed {
		return 1
	}
	return 0
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
