// Command baseline is a client for the baseline experiment.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/baseline"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

// CLI contains command line flags.
type CLI struct {
	TestHelper string          `doc:"overrides the TestHelper address (default: 127.0.0.1)" short:"T"`
	Help       bool            `doc:"prints this help message" short:"h"`
	Verbose    getoptx.Counter `doc:"enable verbose mode" short:"v"`
}

// getopt parses command line options.
func getopt() (*CLI, string) {
	opts := &CLI{
		TestHelper: "127.0.0.1",
		Help:       false,
	}
	parser := getoptx.MustNewParser(opts, getoptx.JustOnePositionalArgument())
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if opts.Verbose > 0 {
		logcat.IncrementLogLevel(int(opts.Verbose))
	}
	return opts, parser.Args()[0]
}

func main() {
	opts, target := getopt()
	ctx, cancel := context.WithCancel(context.Background())
	clnt := &baseline.Client{}
	wg := &sync.WaitGroup{}
	logcat.StartConsumer(ctx, logcat.DefaultLogger(os.Stderr, 0), false, wg)
	begin := time.Now()
	tk, err := clnt.Measure(ctx, target, opts.TestHelper)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s\n", err.Error())
		os.Exit(1)
	}
	data, err := json.Marshal(tk.ToArchival(begin))
	runtimex.PanicOnError(err, "json.Marshal failed")
	fmt.Printf("%s\n", string(data))
	cancel()  // "sighup" to logs writer
	wg.Wait() // wait for all logs to be written
}
