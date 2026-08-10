package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// cmdExec is the executor daemon, which forks brokered commands and holds
// nothing.  To run one, use `faramir run`, which asks the broker, which asks
// this.  Named for its account and unit (faramir-exec).
func cmdExec(args []string) int {
	fs := newFlagSet("exec", "exec [-c PATH]")
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(),
			"usage: faramir exec [-c PATH]\n\n"+
				"The executor daemon, run by faramir-exec.service.  To run a command\n"+
				"through the broker, use `faramir run`.\n\noptions:\n")
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to config.toml (default $FARAMIR_CONFIG, then the installed one)")
	fs.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	// See cmdBroker.
	log.SetFlags(0)
	log.SetPrefix("faramir-exec: ")

	if *showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := config.Load(resolveDaemonConfig(*configPath))
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	e := execserver.New(cfg)
	if _, err := e.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer func() { _ = e.Close() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		log.Printf("shutting down")
		_ = e.Close()
	}()

	sockutil.NotifyReady()
	if err := e.Serve(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}
