package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/monkburger/taberna/internal/config"
	tabernamime "github.com/monkburger/taberna/internal/mime"
	"github.com/monkburger/taberna/internal/server"
)

// version and buildTime are stamped at compile time via -ldflags
// (see Makefile).  The defaults here are used for development builds.
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	cfgPath := flag.String("config", "taberna.toml", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("taberna %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("taberna: %v", err)
	}

	if err := tabernamime.Init(cfg.Server.MimeTypesFile); err != nil {
		log.Fatalf("taberna: %v", err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("taberna: %v", err)
	}

	if err := srv.Run(); err != nil {
		log.Fatalf("taberna: %v", err)
	}
}
