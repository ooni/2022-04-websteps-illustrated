package measurex

//
// Crawler
//
// Contains the crawler implementation.
//

import (
	"context"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// Crawler starts from an input URL and visits the forest
// of all the URLs deriving from such an URL.
//
// Please, either use NewCrawler to create a new instance or
// ensure you initialize all this struct's fields.
type Crawler struct {
	// DNSParallelism is the DNS parallelism to use.
	DNSParallelism int

	// EndpointParallelism is the endpoints parallelism to use.
	EndpointParallelism int

	// Logger is the logger.
	Logger model.Logger

	// MaxDepth is the maximum visit depth.
	MaxDepth int

	// Measurer is the measurer to use.
	Measurer *Measurer

	// Resolvers contains the resolvers to use.
	Resolvers []*DNSResolverInfo
}

// NewCrawler creates a new instance of Crawler.
func NewCrawler(logger model.Logger, measurer *Measurer) *Crawler {
	return &Crawler{
		DNSParallelism:      4,
		EndpointParallelism: 16,
		Logger:              logger,
		Measurer:            measurer,
		MaxDepth:            10,
		Resolvers: []*DNSResolverInfo{{
			Network: "system",
			Address: "",
		}},
	}
}

// Crawl visits the given URL.
func (c *Crawler) Crawl(ctx context.Context, URL string) (<-chan *URLMeasurement, error) {
	mx := c.Measurer
	um, err := mx.NewURLMeasurement(URL)
	if err != nil {
		return nil, err
	}
	out := make(chan *URLMeasurement)
	go func() {
		defer close(out)
		q := NewURLRedirectDeque()
		q.Append(um)
		for !q.Empty() && q.NumRedirects() < c.MaxDepth {
			um = q.PopLeft()
			c.Logger.Infof("🧐 crawling %s", um.URL.String())
			c.do(ctx, mx, um)
			q.RememberVisitedURLs(um)
			redirects, _ := mx.Redirects(um)
			out <- um
			q.Append(redirects...)
			c.Logger.Infof("🪀 work queue: %s", q.String())
		}
	}()
	return out, nil
}

// do visits the URL described by um using the mx Measurer.
func (c *Crawler) do(ctx context.Context, mx *Measurer, um *URLMeasurement) {
	c.Logger.Info("🔎 resolving the domain name using all resolvers")
	dnsPlan := um.NewDNSLookupPlan(c.Resolvers)
	for m := range mx.DNSLookups(ctx, c.DNSParallelism, dnsPlan) {
		um.DNS = append(um.DNS, m)
	}
	c.Logger.Info("🔎 visiting all endpoints deriving from DNS")
	epntPlan, _ := um.NewEndpointPlan()
	for m := range mx.MeasureEndpoints(ctx, c.EndpointParallelism, epntPlan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	c.Logger.Info("🔎 visiting extra endpoints deriving from Alt-Svc (if any)")
	epntPlan, _ = um.NewEndpointPlan()
	for m := range mx.MeasureEndpoints(ctx, c.EndpointParallelism, epntPlan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
}
