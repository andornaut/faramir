package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// cmdKeeper holds the age key and serves decrypted values, as a uid of its own
// that executes nothing but sops.
func cmdKeeper(args []string) int {
	fs := newFlagSet("keeper", "keeper [-c PATH] [--check]")
	configPath := fs.String("config", "", "path to config.toml")
	fs.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	check := fs.Bool("check", false, "decrypt once and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	// See cmdBroker.
	log.SetFlags(0)
	log.SetPrefix("faramir-keeper: ")

	if *showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	k := keeper.New(cfg)

	if *check {
		values, errs := keeper.DecryptAll(cfg.Secrets, k.Keys)
		if errs == nil {
			errs = []string{}
		}
		// Names only, even for the operator.
		out, _ := json.MarshalIndent(map[string]any{
			"refs": keeper.SortedRefs(values), "errors": errs,
		}, "", "  ")
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
