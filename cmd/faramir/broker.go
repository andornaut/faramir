package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/server"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// brokerFlags is the secrets broker daemon: policy, redaction, the audit log
// and the SSH keys. systemd runs it as its own uid, which is the boundary.
type brokerFlags struct {
	check       bool
	parseOnly   bool
	showVersion bool
}

func newBrokerCmd() *cobra.Command {
	var f brokerFlags
	c := &cobra.Command{
		Use:     "broker",
		Short:   "Run the secrets broker daemon",
		GroupID: groupInternal,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runBroker(f)) },
	}
	c.Flags().BoolVar(&f.check, "check", false, "validate config and exit")
	// Whether a config parses, judged by the parser that will judge it later.
	// Distinct from --check, which also opens the SSH keys and the secrets files
	// and so needs a running keeper.
	c.Flags().BoolVar(&f.parseOnly, "parse-only", false, "load the config, report whether it is valid, and exit")
	c.Flags().BoolVar(&f.showVersion, "version", false, "print the version and exit")
	return c
}

func runBroker(f brokerFlags) int {

	// The global logger: the internal packages log through it, and systemd runs
	// one role per process.
	log.SetFlags(0)
	log.SetPrefix("faramir-broker: ")
	undumpable("faramir-broker")

	// Before the config is loaded, so --version answers on a broken host.
	if f.showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := loadDaemonConfig()
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	// Before Reload: the installer calls this before anything is started, and
	// reaching here means the config loaded.
	if f.parseOnly {
		return 0
	}

	s := server.New(cfg)
	s.Store.Reload()

	// Before starting the agent: --check runs against a live broker, and a second
	// agent would replace its socket and outlive this process.
	if f.check {
		body, code := s.CheckOutput()
		fmt.Println(string(body))
		return code
	}

	// No gate here: exec and redact refuse per request instead. Exiting would
	// take down the process `faramir status` and `doctor` ask.
	if reason := s.Store.Unreadable(); reason != "" {
		log.Printf("refusing exec and redact: %s", reason)
		log.Printf("every command the agent hook wraps has its output withheld until this is fixed. " +
			"status and refs still answer; encrypt a file into the secrets directory, and no " +
			"restart is needed")
	} else if reason := s.Store.EmptySet(); reason != "" {
		log.Printf("serving with an empty value set: %s", reason)
		log.Printf("commands run and their output is redacted against nothing, there being nothing to " +
			"redact. That is right for a host managing no credentials and wrong for a store on " +
			"a filesystem that is not mounted, which looks the same from here")
	}

	// Same shape: said at startup so an operator finds out here, and asked again
	// per request, a filesystem filling after boot.
	if reason := s.Audit.Unwritable(); reason != "" {
		log.Printf("refusing every brokered command: the audit log cannot be "+
			"written: %s", reason)
		log.Printf("a command that cannot be recorded is not run, so this is the whole install rather " +
			"than one feature of it. Free space, or point [audit] log_path somewhere with room")
	}

	sshErr := s.Ssh.Start()
	// Covers Listen: a failed bind must not leave an agent holding the fleet keys
	// on a reachable socket.
	defer s.Ssh.Stop()
	// Logged, not fatal: a key the agent does not hold breaks only commands that
	// reach a managed host, and those fail at the point of use with ssh's own
	// error. `--check` and `doctor` both fail on it. An unset [ssh] key is not
	// this: Start reports no error.
	if sshErr != nil {
		log.Printf("ssh-agent: %v", sshErr)
		log.Printf("no SSH identity is loaded, so every brokered command that " +
			"reaches a managed host will fail to authenticate. Place the key and " +
			"restart faramir-broker, or unset [ssh] key")
	}

	// Nothing to start: escalation binds no socket and holds no credential, so
	// the only thing to arrange is releasing whatever is waiting when this
	// stops.
	defer s.Escalation.Stop()

	if _, err := s.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer func() { _ = s.Close() }()

	// No SIGHUP: an edit is picked up by the mtime poll, and a change to
	// config.toml means restarting both daemons, the file list this process
	// started with being the one the keeper decrypts.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		log.Printf("shutting down")
		_ = s.Close()
	}()

	sockutil.NotifyReady()
	if err := s.Serve(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}
