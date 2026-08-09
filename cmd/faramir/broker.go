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
	configPath := fs.String("config", "", "path to config.toml")
	fs.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	check := fs.Bool("check", false, "validate config and exit")
	// Whether a config parses, judged by the parser that will judge it later.
	// Distinct from --check, which also opens the SSH keys and the secrets
	// files and so needs a running keeper.
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

	cfg, err := config.Load(*configPath)
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

	// Before starting the agent: --check runs against a live broker, and a
	// second agent would replace its socket and outlive this process.
	if *check {
		body, code := s.CheckOutput()
		fmt.Println(string(body))
		return code
	}

	// The same gate --check applies, applied where it decides something.
	//
	// --check is the install gate: init runs it, and so does doctor. Neither
	// runs at boot, so until now the claim that a file the broker cannot load
	// "stops the daemon rather than coming up redacting nothing" held only for
	// the state of the host at install time. A store on a filesystem that is
	// not mounted yet, a managed file replaced with one that does not decrypt,
	// a keeper that will not start: each of those left this process binding its
	// socket and serving with a value set that was short or, on a cold start,
	// empty. Nothing was redacted and every unit reported itself active.
	//
	// So it is fatal here too. The unit restarts on failure, which is the right
	// answer for the cases that resolve themselves -- a volume that mounts a
	// moment later, a keeper still starting -- and for the rest it is a broker
	// that is visibly down instead of one that is quietly not redacting.
	//
	// A keeper that cannot be reached counts, this being a cold start with no
	// previous value set to fall back on. The unit already Requires= its socket,
	// so activation supplies it; failing here is what makes the difference
	// between "not up yet" and "up, holding nothing" visible.
	//
	// Startup only. The same failure later keeps the last set the broker knew
	// to be true, which is the better answer once there is one.
	if failures := s.Store.LoadErrors(); len(failures) > 0 {
		log.Printf("%d secret load failure(s): %v", len(failures), failures)
		log.Printf("refusing to start: those values are absent from the redactor, " +
			"so a command that printed one would print it in plaintext")
		return 1
	}

	s.Ssh.Start()
	// Covers Listen: a failed bind must not leave an agent holding the fleet
	// keys on a reachable socket.
	defer s.Ssh.Stop()

	if _, err := s.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer func() { _ = s.Close() }()

	// No SIGHUP: an edit is picked up by the mtime poll, and a change to
	// config.toml means restarting both daemons, since the file list this
	// process started with is the one the keeper decrypts.
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
