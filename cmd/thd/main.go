// Command thd is the test helper daemon.
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

type CLI struct {
	Address     string          `doc:"address where to listen (default: \":9876\")" short:"A"`
	CacheDir    string          `doc:"directory where to store cache (default: empty)" short:"C"`
	Help        bool            `doc:"prints this help message" short:"h"`
	MostlyCache bool            `doc:"never expire cache entries and keep adding to the cache"`
	User        string          `doc:"user to drop privileges to (Linux only; default: nobody)" short:"u"`
	Verbose     getoptx.Counter `doc:"enable verbose mode" short:"v"`
}

// getopt parses command line options.
func getopt() *CLI {
	opts := &CLI{
		Address:     ":9876",
		CacheDir:    "",
		Help:        false,
		MostlyCache: false,
		User:        "nobody",
		Verbose:     0,
	}
	parser := getoptx.MustNewParser(opts, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if opts.Verbose > 0 {
		logcat.IncrementLogLevel(int(opts.Verbose))
	}
	return opts
}

// maybeOpenCache opens the cache if we configured a cache. Otherwise
// this function returns a nil pointer indicating there's no cache.
func maybeOpenCache(ctx context.Context, opts *CLI) (*measurex.Cache, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	if opts.CacheDir == "" {
		return nil, cancel
	}
	cache := measurex.NewCache(opts.CacheDir)
	cache.StartTrimmer(ctx)
	return cache, cancel
}

func main() {
	opts := getopt()
	dropprivileges(opts.User) // must drop before touching the disk
	cache, cancel := maybeOpenCache(context.Background(), opts)
	defer cancel()
	thOptions := &websteps.THHandlerOptions{
		MeasurerFactory: func(options *measurex.Options) (measurex.AbstractMeasurer, error) {
			lib := measurex.NewDefaultLibrary()
			mx := measurex.NewMeasurerWithOptions(lib, options)
			if cache == nil {
				return mx, nil
			}
			var cpp measurex.CachingPolicy
			switch opts.MostlyCache {
			case true:
				cpp = measurex.CachingForeverPolicy()
			case false:
				cpp = measurex.ReasonableCachingPolicy()
			}
			cmx := measurex.NewCachingMeasurer(mx, cache, cpp)
			return cmx, nil
		},
		Resolvers: nil,
		Saver:     nil,
	}
	logcat.StartConsumer(context.Background(), logcat.DefaultLogger(os.Stderr), false)
	thh := websteps.NewTHHandler(thOptions)
	http.Handle("/", thh)
	logcat.Infof("Listening at: \"%s\"", opts.Address)
	http.ListenAndServe(opts.Address, nil)
}
