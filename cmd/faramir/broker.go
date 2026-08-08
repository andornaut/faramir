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

// cmdBroker is the secret broker daemon: policy, redaction, the audit log and
// the SSH keys.  systemd runs it as its own uid, which is the boundary; being a
// subcommand of this binary rather than a binary of its own changes nothing
// about what it can reach.
func cmdBroker(args []string) int {
	fs := newFlagSet("broker", "broker [-c PATH] [--check] [--parse-only]")
	configPath := fs.String("config", "", "path to config.toml")
	fs.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	check := fs.Bool("check", false, "validate config and exit")
	// The installers need to know whether a config parses before they write
	// anything, and they need it judged by the parser that will judge it later:
	// quoting styles and trailing comments have to be read the same way, or a
	// perfectly correct config is refused by a check of its own.  Distinct from
	// --check, which also opens the SSH keys and the secrets files and so needs
	// a keeper that is running.
	parseOnly := fs.Bool("parse-only", false, "load the config, report whether it is valid, and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	// The global logger, deliberately: every internal package logs through it,
	// so a local one would leave those lines unprefixed.  Safe because systemd
	// runs one role per process and no subcommand calls another.
	log.SetFlags(0)
	log.SetPrefix("faramir-broker: ")

	// Before the config is loaded: --version has to answer on a host whose
	// config is broken, which is when someone is most likely to ask.
	if *showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	// Before Reload: this must work without a running keeper, because the
	// installer calls it before anything has been started.  Reaching here at
	// all means the config loaded, so there is nothing left to say.
	if *parseOnly {
		return 0
	}

	s := server.New(cfg)
	s.Store.Reload()

	// Before starting the agent: --check runs against a live broker, and
	// starting a second agent would replace the running one's socket and
	// outlive this process with the fleet keys loaded.
	if *check {
		body, code := s.CheckOutput()
		fmt.Println(string(body))
		return code
	}

	s.Ssh.Start()
	// Covers Listen too: a failed bind must not leave an agent holding the
	// fleet keys on a socket the executor's group can already reach.
	defer s.Ssh.Stop()

	if _, err := s.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer func() { _ = s.Close() }()

	// No SIGHUP.  An edit to a managed file is picked up by the mtime poll
	// within refresh_interval_sec, and a change to config.toml is not something
	// a signal could apply: the file list this process started with is the one
	// the keeper decrypts, so adopting a new one means restarting both.
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
