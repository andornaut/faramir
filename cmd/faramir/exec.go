package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// cmdExec is the executor daemon, which forks brokered commands and holds
// nothing. To run one, use `faramir run`, which asks the broker, which asks
// this. Named for its account and unit (faramir-exec).
type execFlags struct {
	showVersion bool
}

func newExecCmd() *cobra.Command {
	var f execFlags
	c := &cobra.Command{
		Use:   "exec",
		Short: "The executor daemon (to run a command, see \"run\" above)",
		Long: "The executor daemon, run by faramir-exec.service. To run a command\n" +
			"through the broker, use `faramir run`.",
		GroupID: groupInternal,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runExec(f)) },
	}
	c.Flags().BoolVar(&f.showVersion, "version", false, "print the version and exit")
	return c
}

func runExec(f execFlags) int {
	// See cmdBroker.
	log.SetFlags(0)
	log.SetPrefix("faramir-exec: ")
	undumpable("faramir-exec")

	if f.showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := config.Load(resolveDaemonConfig())
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
