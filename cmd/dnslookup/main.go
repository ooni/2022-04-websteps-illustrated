// Command dnslookup allows to perform DNS lookups.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Help     bool     `doc:"prints this help message" short:"h"`
	NS       bool     `doc:"also queries for NS" short:"N"`
	Resolver []string `doc:"resolver to use (default: 8.8.4.4:53)" short:"r"`
	Verbose  bool     `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
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
	var plans []*measurex.DNSLookupPlan
	for _, reso := range opts.Resolver {
		for _, domain := range parser.Args() {
			plan := &measurex.DNSLookupPlan{
				URLMeasurementID: 0,
				URL: &url.URL{
					Host: domain,
				},
				Options: &measurex.Options{},
				Resolvers: []*measurex.DNSResolverInfo{{
					Network: "udp",
					Address: reso,
				}},
				Flags: 0,
			}
			if opts.NS {
				plan.Flags |= measurex.DNSLookupFlagNS
			}
			plans = append(plans, plan)
		}
	}
	begin := time.Now()
	library := measurex.NewDefaultLibrary(log.Log)
	mx := measurex.NewMeasurer(log.Log, library)
	ctx := context.Background()
	for m := range mx.DNSLookups(ctx, plans...) {
		data, err := json.Marshal(m.ToArchival(begin))
		runtimex.PanicOnError(err, "json.Marshal failed")
		fmt.Printf("%s\n", string(data))
	}
}
