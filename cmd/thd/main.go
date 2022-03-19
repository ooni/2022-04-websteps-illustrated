// Command thd is the test helper daemon.
package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/cachex"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

type CLI struct {
	Address  string `doc:"address where to listen (default: \":9876\")" short:"A"`
	CacheDir string `doc:"directory where to store cache" short:"C"`
	Help     bool   `doc:"prints this help message" short:"h"`
	User     string `doc:"user to drop privileges to (Linux only; default: nobody)" short:"u"`
	Verbose  bool   `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
		Address:  ":9876",
		CacheDir: "",
		Help:     false,
		User:     "nobody",
		Verbose:  false,
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
	cache, err := cachex.Open(opts.CacheDir)
	if err != nil {
		log.WithError(err).Fatal("cannot open cache dir")
	}
	olog := measurex.NewOperationLogger(log.Log, "trimming the cache")
	cache.Trim()
	olog.Stop(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go trimCache(ctx, cache)
	thOptions := &websteps.THHandlerOptions{
		Logger: log.Log,
		MeasurerFactory: func(logger model.Logger,
			options *measurex.Options) (measurex.AbstractMeasurer, error) {
			lib := measurex.NewDefaultLibrary(logger)
			mx := measurex.NewMeasurerWithOptions(logger, lib, options)
			cmx := measurex.NewCachingMeasurer(mx, logger, cache, &cachePruningPolicy{})
			return cmx, nil
		},
		Resolvers: nil,
		Saver:     nil,
	}
	thh := websteps.NewTHHandler(thOptions)
	http.Handle("/", thh)
	log.Infof("Listening at: \"%s\"", opts.Address)
	dropprivileges(log.Log, opts.User)
	http.ListenAndServe(opts.Address, nil)
}

func trimCache(ctx context.Context, cache *cachex.Cache) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Note that this does not _actually_ trim the cache but _may_ trim
			// the cache if enough time has passed since last time.
			cache.Trim()
		}
	}
}

type cachePruningPolicy struct{}

var _ measurex.CachingPolicy = &cachePruningPolicy{}

const staleTime = 15 * time.Minute

func (*cachePruningPolicy) StaleDNSLookupMeasurement(m *measurex.CachedDNSLookupMeasurement) bool {
	return m == nil || time.Since(m.T) > staleTime
}

func (*cachePruningPolicy) StaleEndpointMeasurement(m *measurex.CachedEndpointMeasurement) bool {
	return m == nil || time.Since(m.T) > staleTime
}
