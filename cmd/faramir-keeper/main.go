// Command faramir-keeper holds the age key and serves decrypted values.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sockutil"
)

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "", "path to config.toml")
	flag.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	check := flag.Bool("check", false, "decrypt once and exit")
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("faramir-keeper: ")

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
		// Names only.  Even the operator-facing check does not print values.
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
	defer k.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		log.Printf("shutting down")
		_ = k.Close()
	}()

	sockutil.NotifyReady()
	return errCode(k.Serve())
}

func errCode(err error) int {
	if err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}
