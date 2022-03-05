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
	Help    bool     `doc:"prints this help message" short:"h"`
	Input   []string `doc:"add URL to list of URLs to crawl" short:"i"`
	Output  string   `doc:"file where to write output (default: crawler.jsonl)" short:"o"`
	Verbose bool     `doc:"enable verbose mode" short:"v"`
}

func main() {
	cli := &CLI{
		Help:    false,
		Input:   []string{},
		Output:  "crawler.jsonl",
		Verbose: false,
	}
	parser := getoptx.MustNewParser(cli, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if cli.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if cli.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	filep, err := os.Create(cli.Output)
	if err != nil {
		log.WithError(err).Fatal("cannot create output file")
	}
	library := measurex.NewDefaultLibrary(log.Log)
	mx := measurex.NewMeasurer(log.Log, library)
	ctx := context.Background()
	begin := time.Now()
	for _, input := range cli.Input {
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
			data, err := json.Marshal(m.ToArchival(begin))
			if err != nil {
				log.Warnf("cannot serialize JSON: %s", err.Error())
				continue
			}
			if _, err := filep.Write(data); err != nil {
				log.WithError(err).Fatal("cannot write output file")
			}
		}
	}
	if err := filep.Close(); err != nil {
		log.WithError(err).Fatal("cannot close output file")
	}
}
