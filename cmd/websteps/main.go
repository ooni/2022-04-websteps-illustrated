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
	Backend   string          `doc:"backend URL (default: use OONI backend)" short:"b"`
	CacheDir  string          `doc:"optional directory where to store cache (default: none)" short:"C"`
	Deep      bool            `doc:"causes websteps to scan more IP addresses and follow more redirects (slower but more precise)"`
	Emoji     bool            `doc:"enable emitting messages with emojis" short:"e"`
	Fast      bool            `doc:"minimum crawler depth and follows as few IP addresses as possible (faster but less precise)"`
	Help      bool            `doc:"prints this help message" short:"h"`
	Input     []string        `doc:"add URL to list of URLs to crawl" short:"i"`
	InputFile []string        `doc:"add input file containing URLs to crawl" short:"f"`
	Output    string          `doc:"file where to write output (default: report.jsonl)" short:"o"`
	Random    bool            `doc:"shuffle input list before running through it"`
	Raw       bool            `doc:"emit raw websteps format rather than OONI data format"`
	Verbose   getoptx.Counter `doc:"enable verbose mode" short:"v"`
}

// getopt parses command line flags.
func getopt() *CLI {
	opts := &CLI{
		Backend:   "wss://0.th.ooni.org/websteps/v1/th",
		CacheDir:  "",
		Deep:      false,
		Emoji:     false,
		Fast:      false,
		Help:      false,
		Input:     []string{},
		InputFile: []string{},
		Output:    "report.jsonl",
		Random:    false,
		Raw:       false,
		Verbose:   0,
	}
	parser := getoptx.MustNewParser(opts, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if len(opts.Input) < 1 && len(opts.InputFile) < 1 {
		fmt.Fprintf(os.Stderr, "websteps: no input provided (try `./websteps --help' for more help)")
		os.Exit(1)
	}
	if opts.Verbose > 0 {
		logcat.IncrementLogLevel(int(opts.Verbose))
	}
	logcat.SetEnableEmojis(opts.Emoji)
	readInputFiles(opts)
	if opts.Random {
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		rnd.Shuffle(len(opts.Input), func(i, j int) {
			opts.Input[i], opts.Input[j] = opts.Input[j], opts.Input[i]
		})
	}
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

func measurexOptions(opts *CLI) *measurex.Options {
	clientOptions := &measurex.Options{
		MaxAddressesPerFamily: measurex.DefaultMaxAddressPerFamily,
		MaxCrawlerDepth:       measurex.DefaultMaxCrawlerDepth,
	}
	if opts.Deep && opts.Fast {
		fmt.Fprintf(os.Stderr, "websteps: cannot use --deep and --fast together")
		os.Exit(1)
	}
	if opts.Deep {
		clientOptions.MaxAddressesPerFamily = 32
		clientOptions.MaxCrawlerDepth = 11
	} else if opts.Fast {
		clientOptions.MaxAddressesPerFamily = 1
		clientOptions.MaxCrawlerDepth = 1
		clientOptions.MaxHTTPResponseBodySnapshotSize = 1 << 10
		clientOptions.MaxHTTPSResponseBodySnapshotSizeConnectivity = 1 << 10
		clientOptions.MaxHTTPSResponseBodySnapshotSizeThrottling = 1 << 10
	}
	return clientOptions
}

func maybeSetCache(opts *CLI, clnt *websteps.Client) {
	if opts.CacheDir != "" {
		cache := measurex.NewCache(opts.CacheDir)
		clnt.MeasurerFactory = func(options *measurex.Options) (
			measurex.AbstractMeasurer, error) {
			library := measurex.NewDefaultLibrary()
			var mx measurex.AbstractMeasurer = measurex.NewMeasurer(library)
			mx = measurex.NewCachingMeasurer(mx, cache, measurex.CachingForeverPolicy())
			return mx, nil
		}
	}
}

func main() {
	opts := getopt()
	filep, err := os.OpenFile(opts.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	runtimex.Must(err, "cannot create output file")
	begin := time.Now()
	ctx := context.Background()
	clientOptions := measurexOptions(opts)
	clnt := websteps.NewClient(nil, nil, opts.Backend, clientOptions)
	maybeSetCache(opts, clnt)
	go clnt.Loop(ctx)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	logcat.StartConsumer(ctx, logcat.DefaultLogger(os.Stdout))
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
