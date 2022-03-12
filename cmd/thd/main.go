// Command thd is the test helper daemon.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Address string `doc:"address where to listen (default: \":9876\")" short:"A"`
	Help    bool   `doc:"prints this help message" short:"h"`
	Output  string `doc:"file where to save our measurements (default: none)" short:"o"`
	Verbose bool   `doc:"enable verbose mode" short:"v"`
}

func main() {
	opts := &CLI{
		Address: ":9876",
		Help:    false,
		Output:  "",
		Verbose: false,
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
	thOptions := &websteps.THHandlerOptions{
		Logger:    log.Log,
		Resolvers: nil, // use the default
	}
	if opts.Output != "" {
		mw := newMeasurementWriter(opts.Output)
		defer mw.Close()
		thOptions.Saver = mw
	}
	thh := websteps.NewTHHandler(thOptions)
	http.Handle("/", thh)
	log.Infof("Listening at: \"%s\"", opts.Address)
	http.ListenAndServe(opts.Address, nil)
}

type measurementsWriter struct {
	fp io.WriteCloser
	t  time.Time
}

func (mw *measurementsWriter) Save(um *measurex.URLMeasurement) {
	const bodyFlags = 0 // we want to store bodies inline
	data, err := json.Marshal(um.ToArchival(mw.t, bodyFlags))
	runtimex.PanicOnError(err, "json.Marshal failed")
	if _, err := mw.fp.Write(data); err != nil {
		log.WithError(err).Fatal("cannot write into output file")
	}
}

func (mw *measurementsWriter) Close() error {
	if err := mw.fp.Close(); err != nil {
		log.WithError(err).Fatal("cannot close output file")
	}
	return nil
}

func newMeasurementWriter(path string) *measurementsWriter {
	filep, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.WithError(err).Fatal("cannot open output file")
	}
	return &measurementsWriter{
		fp: filep,
		t:  time.Now(),
	}
}
