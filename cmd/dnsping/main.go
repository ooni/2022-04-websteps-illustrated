// Command dnsping allows to send DNS pings.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/dnsping"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
	"github.com/miekg/dns"
)

type CLI struct {
	Count    int      `doc:"number of repetitions" short:"c"`
	Help     bool     `doc:"prints this help message" short:"h"`
	Resolver []string `doc:"resolver to use (default: 8.8.4.4:53)" short:"r"`
	Verbose  bool     `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
		Count:    10,
		Help:     false,
		Resolver: []string{},
		Verbose:  false,
	}
	parser := getoptx.MustNewParser(
		opts, getoptx.AtLeastOnePositionalArgument(),
		getoptx.SetPositionalArgumentsPlaceholder("domain [domain...]"),
	)
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	if len(opts.Resolver) < 1 {
		opts.Resolver = append(opts.Resolver, "8.8.4.4:53")
	}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS}
	var plans []*dnsping.SinglePingPlan
	for _, reso := range opts.Resolver {
		for _, domain := range parser.Args() {
			for _, qtype := range qtypes {
				p := dnsping.NewDefaultPlans(domain, qtype, reso, opts.Count)
				plans = append(plans, p...)
			}
		}
	}
	begin := time.Now()
	engine := dnsping.NewEngine(log.Log, measurex.NewIDGenerator())
	ch := engine.RunAsync(context.Background(), plans)
	result := <-ch
	data, err := json.Marshal(result.ToArchival(begin))
	runtimex.PanicOnError(err, "json.Marshal failed")
	fmt.Printf("%s\n", string(data))
}