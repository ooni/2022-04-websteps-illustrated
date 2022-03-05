package websteps

//
// Client
//
// This file contains the websteps client.
//

import (
	"context"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// TestKeysOrError contains either test keys or an error.
type TestKeysOrError struct {
	// Err is the error that occurred.
	Err error

	// TestKeys are the test keys.
	TestKeys *TestKeys
}

// Client is the websteps client.
type Client struct {
	// Input is the channel for receiving Input.
	Input chan string

	// Output is the channel for emitting measurements.
	Output chan *TestKeysOrError

	// httpClient is the HTTPClient to use.
	httpClient model.HTTPClient

	// logger is the MANDATORY logger to use.
	logger model.Logger

	// resolvers contains the MANDATORY resolvers to use.
	resolvers []*measurex.DNSResolverInfo

	// thURL is the base URL of the test helper.
	thURL string

	// userAgent is the User-Agent to use with the TH.
	userAgent string
}

// THClient is a client for communicating with the test helper.
type THClient interface {
	// THRequestAsync performs an async TH request posting the result on the out channel.
	THRequestAsync(ctx context.Context, thReq *THRequest, out chan<- *THResponseOrError)
}

// NewTHClient creates a new client that does not perform measurements
// and is only suitable for speaking with the TH.
func NewTHClient(logger model.Logger,
	httpClient model.HTTPClient, thURL, userAgent string) THClient {
	return newClient(context.Background(), logger, httpClient, thURL, userAgent, false)
}

// StartClient starts a new websteps client instance in a background goroutine
// and returns the client instance to submit and collect measurements.
func StartClient(ctx context.Context, logger model.Logger,
	httpClient model.HTTPClient, thURL, userAgent string) *Client {
	return newClient(ctx, logger, httpClient, thURL, userAgent, true)
}

// newClient implements NewTHClient and StartClient.
func newClient(ctx context.Context, logger model.Logger, httpClient model.HTTPClient,
	thURL, userAgent string, startBackgroundWorker bool) *Client {
	clnt := &Client{
		Input:      make(chan string),
		Output:     make(chan *TestKeysOrError),
		httpClient: httpClient,
		logger:     logger,
		resolvers:  defaultResolvers(),
		thURL:      thURL,
		userAgent:  userAgent,
	}
	if startBackgroundWorker {
		go clnt.loop(ctx)
	}
	return clnt
}

// loop is the client loop.
func (c *Client) loop(ctx context.Context) {
	for input := range c.Input {
		// Implementation note: with a cancelled context, continue to
		// loop and drain the input channel. The client will eventually
		// notice the context is cancelled and close our input.
		if ctx.Err() == nil {
			c.steps(ctx, input)
		}
	}
	close(c.Output)
}

// steps performs all the steps.
func (c *Client) steps(ctx context.Context, input string) {
	library := measurex.NewDefaultLibrary(c.logger)
	mx := measurex.NewMeasurer(c.logger, library)
	initial, err := mx.NewURLMeasurement(input)
	if err != nil {
		c.logger.Warnf("❌ cannot parse input as URL: %s", err.Error())
		c.Output <- &TestKeysOrError{Err: err}
		return
	}
	q := mx.NewURLRedirectDeque(c.logger)
	q.Append(initial)
	for ctx.Err() == nil { // know that a user has requested to stop
		cur, found := q.PopLeft()
		if !found {
			break // we've emptied the queue
		}
		c.logger.Infof("🧐 depth=%d; crawling %s", q.Depth(), cur.URL.String())
		// Implementation note: here we use a background context for the
		// measurement step because we don't want to interrupt web measurements
		// midway. We'll stop when we enter into the next iteration.
		tk := c.step(context.Background(), mx, cur)
		tk.rememberVisitedURLs(q)
		redirects, _ := tk.redirects(mx)
		c.Output <- &TestKeysOrError{TestKeys: tk}
		q.Append(redirects...)
		c.logger.Infof("🪀 work queue: %s", q.String())
	}
}

// defaultResolvers returns the default resolvers.
func defaultResolvers() []*measurex.DNSResolverInfo {
	// TODO: randomize the resolvers we use...
	return []*measurex.DNSResolverInfo{{
		Network: "system",
		Address: "",
	}, {
		Network: "udp",
		Address: "8.8.8.8:53",
	}, {
		Network: "udp",
		Address: "[2001:4860:4860::8844]:53",
	}}
}

// step performs a single step.
func (c *Client) step(ctx context.Context,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) *TestKeys {
	c.dnsLookup(ctx, mx, cur)
	tk := newTestKeys(cur)
	epntPlan, _ := cur.NewEndpointPlan(0)
	thc := c.th(ctx, cur, epntPlan)
	c.measureDiscoveredEndpoints(ctx, mx, cur, epntPlan)
	c.measureAltSvcEndpoints(ctx, mx, cur)
	maybeTH := <-thc
	if maybeTH.Err == nil {
		tk.TH = maybeTH.Resp
	}
	c.measureAdditionalEndpoints(ctx, mx, tk)
	tk.analyzeResults(c.logger)
	// TODO(bassosimone): run follow-up experiments
	return tk
}

func (c *Client) dnsLookup(ctx context.Context,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	c.logger.Info("📡 resolving the domain name using all resolvers")
	dnsPlan := cur.NewDNSLookupPlan(c.resolvers)
	for m := range mx.DNSLookups(ctx, dnsPlan) {
		cur.DNS = append(cur.DNS, m)
	}
}

func (c *Client) measureDiscoveredEndpoints(
	ctx context.Context, mx *measurex.Measurer,
	cur *measurex.URLMeasurement, plan []*measurex.EndpointPlan) {
	c.logger.Info("📡 measuring endpoints discovered using the DNS")
	for m := range mx.MeasureEndpoints(ctx, plan...) {
		cur.Endpoint = append(cur.Endpoint, m)
	}
}

func (c *Client) measureAltSvcEndpoints(ctx context.Context,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	c.logger.Info("📡 measuring extra endpoints discovered using Alt-Svc (if any)")
	epntPlan, _ := cur.NewEndpointPlan(0)
	for m := range mx.MeasureEndpoints(ctx, epntPlan...) {
		cur.Endpoint = append(cur.Endpoint, m)
	}
}

func (c *Client) measureAdditionalEndpoints(ctx context.Context,
	mx *measurex.Measurer, tk *TestKeys) {
	c.logger.Info("📡 measuring extra endpoints discovered by the TH (if any)")
	// nothing for now
}
