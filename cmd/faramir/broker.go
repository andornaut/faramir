package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/server"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// cmdBroker is the secrets broker daemon: policy, redaction, the audit log and
// the SSH keys.  systemd runs it as its own uid, which is the boundary.
func cmdBroker(args []string) int {
	fs := newFlagSet("broker", "broker [-c PATH] [--check] [--parse-only]")
	configPath := fs.String("config", "", "path to config.toml (default $FARAMIR_CONFIG, then the installed one)")
	fs.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	check := fs.Bool("check", false, "validate config and exit")
	// Whether a config parses, judged by the parser that will judge it later.
	// Distinct from --check, which also opens the SSH keys and the secrets files
	// and so needs a running keeper.
	parseOnly := fs.Bool("parse-only", false, "load the config, report whether it is valid, and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	// The global logger: the internal packages log through it, and systemd runs
	// one role per process.
	log.SetFlags(0)
	log.SetPrefix("faramir-broker: ")

	// Before the config is loaded, so --version answers on a broken host.
	if *showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := config.Load(resolveDaemonConfig(*configPath))
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	// Before Reload: the installer calls this before anything is started, and
	// reaching here means the config loaded.
	if *parseOnly {
		return 0
	}

	s := server.New(cfg)
	s.Store.Reload()

	// Before starting the agent: --check runs against a live broker, and a second
	// agent would replace its socket and outlive this process.
	if *check {
		body, code := s.CheckOutput()
		fmt.Println(string(body))
		return code
	}

	// No gate here: exec and redact refuse per request instead.  Exiting would
	// take down the process `faramir status` and `doctor` ask, which is the
	// process that explains why the secrets are missing.
	if reason := s.Store.Unreadable(); reason != "" {
		log.Printf("refusing exec and redact: %s", reason)
		log.Printf("every command the agent hook wraps has its output withheld " +
			"until this is fixed, which is what keeps an unread file from being " +
			"read past. status and list_secrets still answer; encrypt a file into " +
			"the secrets directory, and no restart is needed")
	}

	sshErr := s.Ssh.Start()
	// Covers Listen: a failed bind must not leave an agent holding the fleet keys
	// on a reachable socket.
	defer s.Ssh.Stop()
	// Logged, not fatal: a key the agent does not hold breaks only commands that
	// reach a managed host, and those fail at the point of use with ssh's own
	// error.  Taking the daemon down over it would stop the commands that never
	// touch SSH and remove the process status and doctor ask.  `--check` and
	// `doctor` both fail on it.
	//
	// An unset [ssh] key is not this: Start reports no error, and the host
	// authenticates however the operator arranged it.
	if sshErr != nil {
		log.Printf("ssh-agent: %v", sshErr)
		log.Printf("no SSH identity is loaded, so every brokered command that " +
			"reaches a managed host will fail to authenticate. Place the key and " +
			"restart faramir-broker, or unset [ssh] key")
	}

	// Nothing to start: approval binds no socket and holds no credential.  A
	// question lives in this process and is answered through the broker's own
	// socket, so the only thing to arrange is releasing whatever is waiting when
	// this stops.
	defer s.Approval.Stop()

	if _, err := s.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer func() { _ = s.Close() }()

	// No SIGHUP: an edit is picked up by the mtime poll, and a change to
	// config.toml means restarting both daemons, since the file list this process
	// started with is the one the keeper decrypts.
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
