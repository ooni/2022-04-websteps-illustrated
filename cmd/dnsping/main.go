// Command dnsping allows to send DNS pings.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bassosimone/getoptx"
	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/dnsping"
	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/measurex"
	"github.com/ooni/2022-04-websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Cache    string          `doc:"directory with dnsping cache" short:"C"`
	Count    int             `doc:"number of repetitions" short:"c"`
	Help     bool            `doc:"prints this help message" short:"h"`
	Resolver []string        `doc:"resolver to use (default: 8.8.4.4:53)" short:"r"`
	Verbose  getoptx.Counter `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
		Count:    10,
		Help:     false,
		Resolver: []string{},
		Verbose:  0,
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
	if opts.Verbose > 0 {
		logcat.IncrementLogLevel(int(opts.Verbose))
	}
	if len(opts.Resolver) < 1 {
		opts.Resolver = append(opts.Resolver, "8.8.4.4:53")
	}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
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
	var engine dnsping.AbstractEngine = dnsping.NewEngine(measurex.NewIDGenerator(), 4*time.Second)
	if opts.Cache != "" {
		cache := dnsping.NewCache(opts.Cache)
		engine = dnsping.NewCachingMeasurer(engine, cache)
	}
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	logcat.StartConsumer(ctx, logcat.DefaultLogger(os.Stderr, 0), false, wg)
	ch := engine.RunAsync(plans)
	result := <-ch
	data, err := json.Marshal(result.ToArchival(begin))
	runtimex.PanicOnError(err, "json.Marshal failed")
	fmt.Printf("%s\n", string(data))
	cancel()  // "sighup" to logs writer
	wg.Wait() // wait for all logs to be written
}
