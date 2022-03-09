// Command thctl is the test helper client.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/apex/log"
	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/engine/experiment/websteps"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

type CLI struct {
	Both         bool     `doc:"ask the test helper to test both HTTP and HTTPS"`
	Help         bool     `doc:"prints this help message" short:"h"`
	Input        string   `doc:"URL to submit to the test helper" short:"i" required:"true"`
	QUICEndpoint []string `doc:"ask the test helper to test this QUIC endpoint"`
	TCPEndpoint  []string `doc:"ask the test helper to test this TCP endpoint"`
	Verbose      bool     `doc:"enable verbose mode" short:"v"`
	URL          string   `doc:"test helper server URL (default: \"ws://127.0.0.1:9876\")" short:"U"`
}

func main() {
	opts := &CLI{
		Both:         false,
		Help:         false,
		Input:        "",
		QUICEndpoint: []string{},
		TCPEndpoint:  []string{},
		Verbose:      false,
		URL:          "ws://127.0.0.1:9876",
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
	request := &websteps.THRequest{
		URL: opts.Input,
		Options: &measurex.Options{
			DoNotInitiallyForceHTTPAndHTTPS: !opts.Both,
		},
		Plan: []websteps.THRequestEndpointPlan{},
	}
	for _, epnt := range opts.QUICEndpoint {
		request.Plan = append(request.Plan, websteps.THRequestEndpointPlan{
			Network: string(archival.NetworkTypeQUIC),
			Address: epnt,
			URL:     opts.Input,
			Cookies: []string{},
		})
	}
	for _, epnt := range opts.TCPEndpoint {
		request.Plan = append(request.Plan, websteps.THRequestEndpointPlan{
			Network: string(archival.NetworkTypeTCP),
			Address: epnt,
			URL:     opts.Input,
			Cookies: []string{},
		})
	}
	clnt := websteps.NewTHClient(log.Log, nil, nil, opts.URL)
	out := make(chan *websteps.THResponseOrError)
	dump(request)
	go clnt.THRequestAsync(context.Background(), request, out)
	maybeResp := <-out
	if maybeResp.Err != nil {
		log.WithError(maybeResp.Err).Fatal("TH failed")
	}
	dump(maybeResp.Resp)
}

func dump(v interface{}) {
	data, err := json.Marshal(v)
	runtimex.PanicOnError(err, "json.Marshal failed")
	fmt.Printf("%s\n", string(data))
}
