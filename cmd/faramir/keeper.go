package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// cmdKeeper holds the age key and serves decrypted values, as a uid of its own
// that executes nothing but sops.
type keeperFlags struct {
	configPath  string
	check       bool
	showVersion bool
}

func newKeeperCmd() *cobra.Command {
	var f keeperFlags
	c := &cobra.Command{
		Use:     "keeper",
		Short:   "holds the age key, serves decrypted values",
		GroupID: groupInternal,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runKeeper(f)) },
	}
	c.Flags().StringVarP(&f.configPath, "config", "c", "", "path to config.toml (default $FARAMIR_CONFIG, then the installed one)")
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

	cfg, err := config.Load(resolveDaemonConfig(f.configPath))
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	k := keeper.New(cfg)

	if f.check {
		values, errs := keeper.DecryptAll(cfg.Secrets, k.Keys)
		if errs == nil {
			errs = []string{}
		}
		// Names only, even for the operator.
		out, err := json.MarshalIndent(map[string]any{
			"refs": keeper.SortedRefs(values), "errors": errs,
		}, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir keeper: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
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
	return keeperErrCode(k.Serve())
}

func keeperErrCode(err error) int {
	if err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}
