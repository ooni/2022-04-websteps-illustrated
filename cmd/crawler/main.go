// Command crawler crawls a set of URLs
package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

type CLI struct {
	Help       bool     `doc:"prints this help message" short:"h"`
	HostHeader string   `doc:"force using this host header"`
	Input      []string `doc:"add URL to list of URLs to crawl" short:"i"`
	Output     string   `doc:"file where to write output (default: crawler.jsonl)" short:"o"`
	SNI        string   `doc:"force using this SNI"`
	Verbose    bool     `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
		Help:       false,
		HostHeader: "",
		Input:      []string{},
		Output:     "crawler.jsonl",
		SNI:        "",
		Verbose:    false,
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
	filep, err := os.OpenFile(opts.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.WithError(err).Fatal("cannot create output file")
	}
	library := measurex.NewDefaultLibrary(log.Log)
	mx := measurex.NewMeasurer(log.Log, library)
	mx.Options = &measurex.Options{
		HTTPHostHeader: opts.HostHeader,
		SNI:            opts.SNI,
	}
	ctx := context.Background()
	begin := time.Now()
	for _, input := range opts.Input {
		crawler := measurex.NewCrawler(log.Log, mx)
		crawler.Resolvers = append(crawler.Resolvers, &measurex.DNSResolverInfo{
			Network: "udp",
			Address: "8.8.4.4:53",
		})
		mchan, err := crawler.Crawl(ctx, input)
		if err != nil {
			log.Warnf("cannot start crawler: %s", err.Error())
			continue
		}
		for m := range mchan {
			const bodyFlags = 0 // serialize the whole body
			data, err := json.Marshal(m.ToArchival(begin, bodyFlags))
			if err != nil {
				log.Warnf("cannot serialize JSON: %s", err.Error())
				continue
			}
			data = append(data, '\n')
			if _, err := filep.Write(data); err != nil {
				log.WithError(err).Fatal("cannot write output file")
			}
		}
	}
	if err := filep.Close(); err != nil {
		log.WithError(err).Fatal("cannot close output file")
	}
}
