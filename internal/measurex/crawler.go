package measurex

//
// Crawler
//
// Contains the crawler implementation.
//

import (
	"context"

	"github.com/bassosimone/websteps-illustrated/internal/logcat"
)

// Crawler starts from an input URL and visits the forest
// of all the URLs deriving from such an URL.
//
// Please, either use NewCrawler to create a new instance or
// ensure you initialize all this struct's fields.
type Crawler struct {
	// Measurer is the measurer to use.
	Measurer AbstractMeasurer

	// Options contains options. If this field is nil, we will
	// end up using the default option values.
	Options *Options

	// Resolvers contains the resolvers to use.
	Resolvers []*DNSResolverInfo
}

// NewCrawler creates a new instance of Crawler.
func NewCrawler(mx AbstractMeasurer) *Crawler {
	return &Crawler{
		Measurer: mx,
		Options:  mx.FlattenOptions(),
		Resolvers: []*DNSResolverInfo{{
			Network: "system",
			Address: "",
		}},
	}
}

// Crawl visits the given URL.
func (c *Crawler) Crawl(ctx context.Context, URL string) (<-chan *URLMeasurement, error) {
	mx := c.Measurer
	initial, err := mx.NewURLMeasurement(URL)
	if err != nil {
		return nil, err
	}
	out := make(chan *URLMeasurement)
	go func() {
		defer close(out)
		q := mx.NewURLRedirectDeque()
		q.Append(initial)
		for {
			cur, found := q.PopLeft()
			if !found {
				break // we've emptied the queue
			}
			logcat.Stepf("depth=%d; crawling %s", q.Depth(), cur.URL.String())
			c.do(ctx, mx, cur)
			q.RememberVisitedURLs(cur.Endpoint)
			redirects, _ := mx.Redirects(cur.Endpoint, cur.Options)
			out <- cur
			q.Append(redirects...)
			logcat.Infof("🪀 work queue: %s", q.String())
		}
	}()
	return out, nil
}

// do visits the URL described by um using mx.
func (c *Crawler) do(ctx context.Context, mx AbstractMeasurer, um *URLMeasurement) {
	logcat.Substep("resolving the domain name using all resolvers")
	const flags = 0 // no extra queries
	dnsPlan := um.NewDNSLookupPlans(flags, c.Resolvers...)
	for m := range mx.DNSLookups(ctx, dnsPlan...) {
		um.DNS = append(um.DNS, m)
	}
	logcat.Substep("visiting endpoints deriving from DNS")
	epntPlan, _ := um.NewEndpointPlan(0)
	for m := range mx.MeasureEndpoints(ctx, epntPlan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	logcat.Substep("visiting extra endpoints deriving from Alt-Svc (if any)")
	epntPlan, _ = um.NewEndpointPlan(EndpointPlanningOnlyHTTP3)
	for m := range mx.MeasureEndpoints(ctx, epntPlan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
}
