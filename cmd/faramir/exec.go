package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// childUmask is what a brokered command creates files under: 0600 for a file
// and 0700 for a directory, so an artifact left behind is not readable by the
// account that asked for the command. See the note at the call.
const childUmask = 0o077

// cmdExec is the executor daemon, which forks brokered commands and holds
// nothing. To run one, use `faramir run`, which asks the broker, which asks
// this. Named for its account and unit (faramir-exec).
type execFlags struct {
	showVersion bool
}

func newExecCmd() *cobra.Command {
	var f execFlags
	c := &cobra.Command{
		Use:     "exec",
		Short:   "Run the executor daemon",
		Long:    "Runs the executor daemon, started by faramir-exec.service.",
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

	cfg, err := loadDaemonConfig()
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	// Every brokered command inherits this, and what it decides is whether an
	// artifact one leaves behind can be read by the agent that asked for it.
	//
	// It can otherwise, because the executor writes where the agent reads. Only
	// /tmp and /var/tmp are private per unit: /dev/shm is shared with the caller.
	// And the executor is in the operator's group so that brokered work can build
	// in the project tree, which means it can leave a file there too. Reading back
	// a file a command just rendered is ordinary work, and a file tool's output
	// goes through no redactor.
	//
	// A default rather than a cap: a command that means to publish its output says
	// `umask` and overrides this. Set here rather than in execserver.New so that
	// constructing an Executor in a test does not change the test process's own.
	//
	// After loadDaemonConfig and before Listen, which sets and restores a umask of
	// its own around the bind.
	unix.Umask(childUmask)

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
