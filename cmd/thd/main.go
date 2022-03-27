// Command thd is the test helper daemon.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Address             string          `doc:"address where to listen (default: \":9876\")" short:"A"`
	CacheDir            string          `doc:"directory where to store cache (default: empty)" short:"C"`
	CacheDisableNetwork bool            `doc:"the cache would not rely on the network to fill missing entries" short:"N"`
	CacheForever        bool            `doc:"never expire cache entries and keep adding to the cache"`
	Help                bool            `doc:"prints this help message" short:"h"`
	Logfile             string          `doc:"write logs to the specified file instead of to stderr" short:"L"`
	User                string          `doc:"user to drop privileges to (Linux only; default: nobody)" short:"u"`
	Verbose             getoptx.Counter `doc:"enable verbose mode" short:"v"`
}

// getopt parses command line options.
func getopt() *CLI {
	opts := &CLI{
		Address:             ":9876",
		CacheDir:            "",
		CacheDisableNetwork: false,
		CacheForever:        false,
		Help:                false,
		Logfile:             "",
		User:                "nobody",
		Verbose:             0,
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

// maybeOpenCache opens the cache if we configured a cache. Otherwise this
// function returns a nil pointer and false indicating there's no cache.
func maybeOpenCache(ctx context.Context, opts *CLI) (*measurex.Cache, bool) {
	if opts.CacheDir == "" {
		return nil, false
	}
	fmt.Fprintf(os.Stderr, "thd: using cache at %s with disableNetwork=%v\n",
		opts.CacheDir, opts.CacheDisableNetwork)
	cache := measurex.NewCache(opts.CacheDir)
	cache.DisableNetwork = opts.CacheDisableNetwork
	cache.StartTrimmer(ctx)
	return cache, true
}

// handleSignals handles signals.
func handleSignals(cancel context.CancelFunc) {
	// See https://gobyexample.com/signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	logcat.Noticef("got signal %d", sig)
	cancel()
}

// shutdown shuts down the HTTP server.
func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// openlog opens the log file and returns the function to close it.
func openlog(opts *CLI) (*os.File, func()) {
	if opts.Logfile != "" {
		filep, err := os.OpenFile(opts.Logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		runtimex.Must(err, "thd: cannot open logfile")
		cancel := func() {
			err := filep.Close()
			runtimex.Must(err, "thd: cannot close logfile")
		}
		fmt.Fprintf(os.Stderr, "thd: redirecting logs to %s\n", opts.Logfile)
		return filep, cancel
	}
	return os.Stderr, func() {}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	opts := getopt()

	// 1. start listening very early so we can take advantage of possible root
	// privileges for opening privileged ports and report listening issues early
	listener, err := net.Listen("tcp", opts.Address)
	runtimex.Must(err, "thd")
	fmt.Fprintf(os.Stderr, "thd: listening at: \"%s\"\n", opts.Address)

	// 2. drop root privileges if needed. This function must run first and
	// for sure before we attempt to write to the disk. Files will have wrong
	// ownership if we drop privileges after writing to the disk.
	dropprivileges(opts.User)

	// 3. open cache and setup a periodic trimming goroutine.
	cache, hasCache := maybeOpenCache(ctx, opts)

	// 4. construct THHandler with options that use the cache if needed.
	thOptions := &websteps.THHandlerOptions{
		MeasurerFactory: func(options *measurex.Options) (measurex.AbstractMeasurer, error) {
			lib := measurex.NewDefaultLibrary()
			mx := measurex.NewMeasurerWithOptions(lib, options)
			if !hasCache {
				return mx, nil
			}
			var cpp measurex.CachingPolicy
			switch opts.CacheForever {
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
	thh := websteps.NewTHHandler(thOptions)

	// 5. configure logging
	logfp, closelog := openlog(opts)
	defer closelog()
	logger := logcat.DefaultLogger(logfp, logcat.DefaultLoggerWriteTimestamps)
	logcat.StartConsumer(ctx, logger, false)

	// 6. handle SIGINT and SIGTERM in the background
	go handleSignals(cancel)

	// 7. configure and start the HTTP server in the background
	mux := http.NewServeMux()
	mux.Handle("/", thh)
	srv := &http.Server{Addr: opts.Address, Handler: mux}
	go srv.Serve(listener)

	// 8. wait for signals to happen
	<-ctx.Done()

	// 9. shutdown the server
	shutdown(srv)
}
