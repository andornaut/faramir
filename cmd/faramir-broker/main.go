// Command faramir-broker is the secret broker daemon.
package main

import (
	"flag"
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

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "", "path to config.toml")
	flag.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	check := flag.Bool("check", false, "validate config and exit")
	// The installers need to know whether a config parses before they write
	// anything, and they need it judged by the parser that will judge it later:
	// quoting styles and trailing comments have to be read the same way, or a
	// perfectly correct config is refused by a check of its own.  Distinct from
	// --check, which also opens the SSH keys and the secrets files and so needs
	// a keeper that is running.
	parseOnly := flag.Bool("parse-only", false, "load the config, report whether it is valid, and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("faramir-broker: ")

	// Before the config is loaded: --version has to answer on a host whose
	// config is broken, which is when someone is most likely to ask.
	if *showVersion {
		fmt.Println("faramir-broker " + version.Version)
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

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range signals {
			if sig == syscall.SIGHUP {
				s.Reload()
				continue
			}
			log.Printf("shutting down")
			_ = s.Close()
			return
		}
	}()

	sockutil.NotifyReady()
	if err := s.Serve(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}
