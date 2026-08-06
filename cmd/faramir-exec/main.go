// Command faramir-exec runs brokered commands and holds no secrets.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/sockutil"
)

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "", "path to config.toml")
	flag.StringVar(configPath, "c", "", "path to config.toml (shorthand)")
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("faramir-exec: ")

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("%v", err)
		return 2
	}

	e := execserver.New(cfg)
	if _, err := e.Listen(); err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer e.Close()

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
