// Command crawler crawls a set of URLs
package main

import (
	"bufio"
	"context"
	"os"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/cachex"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

type CLI struct {
	CacheDir   string   `doc:"directory where to store cache" short:"C"`
	Help       bool     `doc:"prints this help message" short:"h"`
	HostHeader string   `doc:"force using this host header"`
	Input      []string `doc:"add URL to list of URLs to crawl" short:"i"`
	InputFile  []string `doc:"add input file containing URLs to crawl" short:"f"`
	SNI        string   `doc:"force using this SNI"`
	Verbose    bool     `doc:"enable verbose mode" short:"v"`
}

// getopt parses command line flags.
func getopt() *CLI {
	opts := &CLI{
		CacheDir:   "",
		Help:       false,
		HostHeader: "",
		Input:      []string{},
		InputFile:  []string{},
		SNI:        "",
		Verbose:    false,
	}
	parser := getoptx.MustNewParser(opts, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if opts.Help || (len(opts.Input) < 1 && len(opts.InputFile) < 1) {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	readInputFiles(opts)
	return opts
}

// readInputFiles reads the input files.
func readInputFiles(opts *CLI) {
	for _, inputfile := range opts.InputFile {
		inputs := readInputFile(inputfile)
		opts.Input = append(opts.Input, inputs...)
	}
}

// readInputFile reads a single input file.
//
// Note: this is a simplified version of a much better function that
// we have in probe-cli and checks also for empty files.
func readInputFile(filepath string) (inputs []string) {
	fp, err := os.Open(filepath)
	if err != nil {
		log.WithError(err).Fatal("cannot open input file")
	}
	defer fp.Close()
	// Implementation note: when you save file with vim, you have newline at
	// end of file and you don't want to consider that an input line. While there
	// ignore any other empty line that may occur inside the file.
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			inputs = append(inputs, line)
		}
	}
	if scanner.Err() != nil {
		log.WithError(err).Fatal("scanner error while processing input file")
	}
	return
}

// newMeasurer creates a new AbstractMeasurer.
func newMeasurer(opts *CLI) measurex.AbstractMeasurer {
	library := measurex.NewDefaultLibrary(log.Log)
	mx := measurex.NewMeasurer(log.Log, library)
	mx.Options = &measurex.Options{
		HTTPExtractTitle:                             true,
		HTTPHostHeader:                               opts.HostHeader,
		MaxAddressesPerFamily:                        32,
		MaxCrawlerDepth:                              16,
		MaxHTTPResponseBodySnapshotSize:              1 << 22,
		MaxHTTPSResponseBodySnapshotSizeConnectivity: 1 << 22,
		MaxHTTPSResponseBodySnapshotSizeThrottling:   1 << 22,
		SNI: opts.SNI,
	}
	var amx measurex.AbstractMeasurer = mx
	if opts.CacheDir != "" {
		cache, err := cachex.Open(opts.CacheDir)
		if err != nil {
			log.WithError(err).Fatal("cannot open cache dir")
		}
		amx = measurex.NewCachingMeasurer(amx, log.Log,
			cache, measurex.CachingForeverPolicy())
	}
	return amx
}

// newCrawler creates a new crawler.
func newCrawler(opts *CLI, amx measurex.AbstractMeasurer) *measurex.Crawler {
	crawler := measurex.NewCrawler(log.Log, amx)
	crawler.Resolvers = []*measurex.DNSResolverInfo{{
		Network: "doh",
		Address: "https://dns.google/dns-query",
	}}
	return crawler
}

func main() {
	opts := getopt()
	amx := newMeasurer(opts)
	ctx := context.Background()
	for _, input := range opts.Input {
		crawler := newCrawler(opts, amx)
		mchan, err := crawler.Crawl(ctx, input)
		if err != nil {
			log.Warnf("cannot start crawler: %s", err.Error())
			continue
		}
		for range mchan {
			// just drain the channel
		}
	}
}
