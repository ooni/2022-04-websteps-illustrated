// Command thctl is the test helper client.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Archival     bool     `doc:"show results in the OONI archival data format"`
	Backend      string   `doc:"test helper server URL (default: \"ws://127.0.0.1:9876\")" short:"b"`
	Both         bool     `doc:"ask the test helper to test both HTTP and HTTPS"`
	Help         bool     `doc:"prints this help message" short:"h"`
	Input        string   `doc:"URL to submit to the test helper" short:"i" required:"true"`
	QUICEndpoint []string `doc:"ask the test helper to test this QUIC endpoint"`
	TCPEndpoint  []string `doc:"ask the test helper to test this TCP endpoint"`
	Verbose      bool     `doc:"enable verbose mode" short:"v"`
}

// getopt gets command line options.
func getopt() *CLI {
	opts := &CLI{
		Archival:     false,
		Backend:      "ws://127.0.0.1:9876",
		Both:         false,
		Help:         false,
		Input:        "",
		QUICEndpoint: []string{},
		TCPEndpoint:  []string{},
		Verbose:      false,
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
	return opts
}

// newRequest creates a new THRequest.
func newRequest(opts *CLI) *websteps.THRequest {
	request := &websteps.THRequest{
		URL: opts.Input,
		Options: &measurex.Options{
			DoNotInitiallyForceHTTPAndHTTPS: !opts.Both,
			HTTPExtractTitle:                true,
		},
		Plan: []websteps.THRequestEndpointPlan{},
	}
	for _, epnt := range opts.QUICEndpoint {
		request.Plan = append(request.Plan, websteps.THRequestEndpointPlan{
			Network: string(archival.NetworkTypeQUIC),
			Address: epnt,
			URL:     opts.Input,
		})
	}
	for _, epnt := range opts.TCPEndpoint {
		request.Plan = append(request.Plan, websteps.THRequestEndpointPlan{
			Network: string(archival.NetworkTypeTCP),
			Address: epnt,
			URL:     opts.Input,
		})
	}
	return request
}

func main() {
	opts := getopt()
	request := newRequest(opts)
	clnt := websteps.NewTHClientWithDefaultSettings(opts.Backend)
	dump(request)
	begin := time.Now()
	resp, err := clnt.THRequest(context.Background(), request)
	if err != nil {
		log.WithError(err).Fatal("TH failed")
	}
	if opts.Archival {
		dump(resp.ToArchival(begin))
		return
	}
	dump(resp)
}

// dump emits a JSON result to the stdout.
func dump(v interface{}) {
	data, err := json.Marshal(v)
	runtimex.PanicOnError(err, "json.Marshal failed")
	fmt.Printf("%s\n", string(data))
}
