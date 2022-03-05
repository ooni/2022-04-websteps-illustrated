// Command thd is the test helper daemon.
package main

import (
	"net/http"
	"os"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
)

type CLI struct {
	Address string `doc:"address where to listen (default: \":9876\")" short:"A"`
	Help    bool   `doc:"prints this help message" short:"h"`
	Verbose bool   `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
		Address: ":9876",
		Help:    false,
		Verbose: false,
	}
	parser := getoptx.MustNewParser(opts, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	thh := websteps.NewTHHandler(log.Log)
	http.Handle("/", thh)
	log.Infof("Listening at: \"%s\"", opts.Address)
	http.ListenAndServe(opts.Address, nil)
}
