package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// cmdKeeper holds the age key and serves decrypted values, as a uid of its own
// that executes nothing but sops.
type keeperFlags struct {
	check       bool
	showVersion bool
}

func newKeeperCmd() *cobra.Command {
	var f keeperFlags
	c := &cobra.Command{
		Use:     "keeper",
		Short:   "Run the keeper daemon, which holds the age key",
		GroupID: groupInternal,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runKeeper(f)) },
	}
	c.Flags().BoolVar(&f.check, "check", false, "decrypt once and exit")
	c.Flags().BoolVar(&f.showVersion, "version", false, "print the version and exit")
	return c
}

func runKeeper(f keeperFlags) int {

	// See cmdBroker.
	log.SetFlags(0)
	log.SetPrefix("faramir-keeper: ")

	if f.showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := loadDaemonConfig()
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	k := keeper.New(cfg)

	if f.check {
		values, errs, shadowed := keeper.DecryptAll(cfg.Secret, k.Keys)
		if errs == nil {
			errs = []string{}
		}
		if shadowed == nil {
			shadowed = map[string]string{}
		}
		// Names only, even for the operator.
		if rc := printJSON("keeper", map[string]any{
			"refs": keeper.SortedRefs(values), "errors": errs,
			"shadowed_refs": shadowed,
		}); rc != 0 {
			return rc
		}
		if len(errs) > 0 {
			return 1
		}
		return 0
	}

	if _, err := k.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer func() { _ = k.Close() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		log.Printf("shutting down")
		_ = k.Close()
	}()

	sockutil.NotifyReady()
	if err := k.Serve(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}
