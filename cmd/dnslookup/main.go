// Command dnslookup allows to perform DNS lookups.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

// CLI contains command line flags.
type CLI struct {
	EnableHTTPS    bool            `doc:"also query for HTTPSSvc records"`
	EnableNS       bool            `doc:"also query for NS records"`
	HTTPSResolver  []string        `doc:"add HTTPS resolver URL"`
	Help           bool            `doc:"prints this help message" short:"h"`
	Raw            bool            `doc:"emits measurements in the internal data format"`
	SystemResolver bool            `doc:"use the system resolver"`
	UDPResolver    []string        `doc:"add UDP resolver endpoint"`
	Verbose        getoptx.Counter `doc:"enable verbose mode" short:"v"`
}

// getopt parses command line options.
func getopt() (*CLI, []string) {
	opts := &CLI{
		EnableHTTPS:    false,
		EnableNS:       false,
		HTTPSResolver:  []string{},
		Help:           false,
		Raw:            false,
		SystemResolver: false,
		UDPResolver:    []string{},
		Verbose:        0,
	}
	parser := getoptx.MustNewParser(
		opts, getoptx.AtLeastOnePositionalArgument(),
		getoptx.SetPositionalArgumentsPlaceholder("domain [domain...]"),
	)
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if opts.Verbose > 0 {
		logcat.IncrementLogLevel(int(opts.Verbose))
	}
	return opts, parser.Args()
}

// makeplans creates the lookup plans.
func makeplans(opts *CLI, args []string) []*measurex.DNSLookupPlan {
	var (
		plans []*measurex.DNSLookupPlan
		flags int64
	)
	if opts.EnableHTTPS {
		flags |= measurex.DNSLookupFlagHTTPS
	}
	if opts.EnableNS {
		flags |= measurex.DNSLookupFlagNS
	}
	resolvers := measurex.NewResolversUDP(opts.UDPResolver...)
	resolvers = append(resolvers, measurex.NewResolversHTTPS(opts.HTTPSResolver...)...)
	if opts.SystemResolver || len(resolvers) <= 0 {
		if len(resolvers) <= 0 {
			fmt.Println("no resolver specified; using the system resolver")
		}
		resolvers = append(resolvers, &measurex.DNSResolverInfo{
			Network: "system",
			Address: "",
		})
	}
	for _, domain := range args {
		dlps := measurex.NewDNSLookupPlans(
			domain, &measurex.Options{}, flags, resolvers...)
		plans = append(plans, dlps...)
	}
	return plans
}

// dump dumps a measurement in JSON format to the stdout.
func dump(m interface{}) {
	data, err := json.Marshal(m)
	runtimex.PanicOnError(err, "json.Marshal failed")
	fmt.Printf("%s\n", string(data))
}

func main() {
	opts, args := getopt()
	plans := makeplans(opts, args)
	mx := measurex.NewMeasurerWithDefaultSettings()
	begin := time.Now()
	ctx := context.Background()
	logcat.StartConsumer(ctx, logcat.DefaultLogger(os.Stdout, 0), false)
	for m := range mx.DNSLookups(ctx, plans...) {
		if opts.Raw {
			dump(m)
			continue
		}
		dump(m.ToArchival(begin))
	}
}
