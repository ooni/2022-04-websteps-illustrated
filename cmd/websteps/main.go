// Command websteps is a websteps client.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Backend              string          `doc:"backend URL (default: use OONI backend)" short:"b"`
	Emoji                bool            `doc:"enable emitting messages with emojis" short:"e"`
	Help                 bool            `doc:"prints this help message" short:"h"`
	Input                []string        `doc:"add URL to list of URLs to crawl. You must provide input using this option or -f." short:"i"`
	InputFile            []string        `doc:"add input file containing URLs to crawl. You must provide input using this option or -i." short:"f"`
	Mode                 string          `doc:"control depth versus breadth. One of: deep, default, and fast." short:"m"`
	Output               string          `doc:"file where to write output (default: report.jsonl)" short:"o"`
	PredictableResolvers bool            `doc:"always use the same resolver, thus producting a fully reusable probe cache" short:"P"`
	ProbeCacheDir        string          `doc:"optional directory where the probe cache lives. This case is R/W without any pruning policy." short:"C"`
	Random               bool            `doc:"shuffle input list before running through it"`
	Raw                  bool            `doc:"emit raw websteps format rather than OONI data format"`
	THCacheDir           string          `doc:"optional directory where to TH cache lives. This cache is write only. Force a local 'thd' to use it running './thd -C dir'." short:"T"`
	Verbose              getoptx.Counter `doc:"enable verbose mode. Use more than once for more verbosity." short:"v"`
}

// getopt parses command line flags.
func getopt() (getoptx.Parser, *CLI) {
	opts := &CLI{
		Backend:              "wss://0.th.ooni.org/websteps/v1/th",
		Emoji:                false,
		Help:                 false,
		Input:                []string{},
		InputFile:            []string{},
		Mode:                 "default",
		Output:               "report.jsonl",
		PredictableResolvers: false,
		ProbeCacheDir:        "",
		Random:               false,
		Raw:                  false,
		THCacheDir:           "",
		Verbose:              0,
	}
	parser := getoptx.MustNewParser(opts, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if len(opts.Input) < 1 && len(opts.InputFile) < 1 {
		fmt.Fprintf(os.Stderr, "websteps: you need to provide input using -i or -f.\n")
		parser.PrintUsage(os.Stderr)
		os.Exit(1)
	}
	if opts.Verbose > 0 {
		logcat.IncrementLogLevel(int(opts.Verbose))
	}
	readInputFiles(opts)
	if opts.Random {
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		rnd.Shuffle(len(opts.Input), func(i, j int) {
			opts.Input[i], opts.Input[j] = opts.Input[j], opts.Input[i]
		})
	}
	return parser, opts
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
	runtimex.Must(err, "cannot open input file")
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
	runtimex.Must(scanner.Err(), "scanner error while processing input file")
	return
}

func measurexOptions(parser getoptx.Parser, opts *CLI) *measurex.Options {
	clientOptions := &measurex.Options{
		MaxAddressesPerFamily: measurex.DefaultMaxAddressPerFamily,
		MaxCrawlerDepth:       measurex.DefaultMaxCrawlerDepth,
	}
	switch opts.Mode {
	case "deep":
		clientOptions.MaxAddressesPerFamily = 32
		clientOptions.MaxCrawlerDepth = 11
	case "default":
		// nothing to do
	case "fast":
		clientOptions.MaxAddressesPerFamily = 2 // less than may miss DNS censorship
		clientOptions.MaxCrawlerDepth = 1
		clientOptions.MaxHTTPResponseBodySnapshotSize = 1 << 10
		clientOptions.MaxHTTPSResponseBodySnapshotSizeConnectivity = 1 << 10
		clientOptions.MaxHTTPSResponseBodySnapshotSizeThrottling = 1 << 10
	default:
		fmt.Fprintf(os.Stderr, "websteps: invalid argument passed to -m, --mode flag.\n")
		parser.PrintUsage(os.Stderr)
		os.Exit(1)
	}
	return clientOptions
}

func maybeSetCaches(opts *CLI, clnt *websteps.Client) {
	if opts.ProbeCacheDir != "" {
		cache := measurex.NewCache(opts.ProbeCacheDir)
		clnt.MeasurerFactory = func(options *measurex.Options) (
			measurex.AbstractMeasurer, error) {
			library := measurex.NewDefaultLibrary()
			var mx measurex.AbstractMeasurer = measurex.NewMeasurer(library)
			mx = measurex.NewCachingMeasurer(mx, cache, measurex.CachingForeverPolicy())
			return mx, nil
		}
	}
	if opts.THCacheDir != "" {
		cache := measurex.NewCache(opts.THCacheDir)
		clnt.THMeasurementObserver = func(m *websteps.THResponse) {
			for _, d := range m.DNS {
				cache.StoreDNSLookupMeasurement(d)
			}
			for _, e := range m.Endpoint {
				cache.StoreEndpointMeasurement(e)
			}
		}
	}
}

func maybeUsePredictableResolvers(opts *CLI, clnt *websteps.Client) {
	if opts.PredictableResolvers {
		clnt.Resolvers = websteps.PredictableDNSResolvers()
	}
}

func main() {
	parser, opts := getopt()
	filep, err := os.OpenFile(opts.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	runtimex.Must(err, "cannot create output file")
	begin := time.Now()
	ctx := context.Background()
	logcat.StartConsumer(ctx, logcat.DefaultLogger(os.Stdout), opts.Emoji)
	clientOptions := measurexOptions(parser, opts)
	clnt := websteps.NewClient(nil, nil, opts.Backend, clientOptions)
	maybeSetCaches(opts, clnt)
	maybeUsePredictableResolvers(opts, clnt)
	go clnt.Loop(ctx, websteps.LoopFlagGreedy)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go submitInput(ctx, wg, clnt, opts)
	processOutput(begin, filep, clnt, opts.Raw)
	wg.Wait()
	runtimex.Must(filep.Close(), "cannot close output file")
}

func submitInput(ctx context.Context, wg *sync.WaitGroup, clnt *websteps.Client, opts *CLI) {
	defer close(clnt.Input)
	defer wg.Done()
	for _, input := range opts.Input {
		clnt.Input <- input
		if ctx.Err() != nil {
			return
		}
	}
}

// result is the result of running websteps on an input URL.
type result struct {
	// TestKeys contains the experiment test keys.
	TestKeys *websteps.ArchivalTestKeys `json:"test_keys"`
}

func processOutput(begin time.Time, filep io.Writer, clnt *websteps.Client, raw bool) {
	for tkoe := range clnt.Output {
		if err := tkoe.Err; err != nil {
			logcat.Warn(err.Error())
			continue
		}
		if raw {
			store(filep, tkoe.TestKeys)
			continue
		}
		r := &result{TestKeys: tkoe.TestKeys.ToArchival(begin)}
		store(filep, r)
	}
}

func store(filep io.Writer, r interface{}) {
	data, err := json.Marshal(r)
	runtimex.PanicOnError(err, "json.Marshal failed")
	data = append(data, '\n')
	_, err = filep.Write(data)
	runtimex.Must(err, "cannot write output file")
}
