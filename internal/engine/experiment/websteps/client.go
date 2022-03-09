package websteps

//
// Client
//
// This file contains the websteps client.
//

import (
	"context"
	"fmt"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// TestKeys contains the experiment test keys.
type TestKeys struct {
	// URL is the URL this measurement refers to.
	URL string

	// Steps contains all the steps.
	Steps []*SingleStepMeasurement
}

// ArchivalTestKeys contains the archival test keys.
type ArchivalTestKeys struct {
	URL   string                           `json:"url"`
	Steps []*ArchivalSingleStepMeasurement `json:"steps"`
}

// ToArchival converts TestKeys to the archival data format.
func (tk *TestKeys) ToArchival(begin time.Time) (out *ArchivalTestKeys) {
	out = &ArchivalTestKeys{
		URL:   tk.URL,
		Steps: []*ArchivalSingleStepMeasurement{},
	}
	for _, entry := range tk.Steps {
		out.Steps = append(out.Steps, entry.ToArchival(begin))
	}
	return
}

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
		c.Output <- &TestKeysOrError{
			Err:      fmt.Errorf("cannot parse %s: %w", input, err),
			TestKeys: nil,
		}
		return
	}
	q := mx.NewURLRedirectDeque(c.logger)
	q.Append(initial)
	tkoe := &TestKeysOrError{
		Err: nil,
		TestKeys: &TestKeys{
			URL:   input,
			Steps: []*SingleStepMeasurement{},
		},
	}
	for ctx.Err() == nil { // know that a user has requested to stop
		cur, found := q.PopLeft()
		if !found {
			break // we've emptied the queue
		}
		c.logger.Infof("📌 depth=%d; crawling %s", q.Depth(), cur.URL.String())
		// Implementation note: here we use a background context for the
		// measurement step because we don't want to interrupt web measurements
		// midway. We'll stop when we enter into the next iteration.
		ssm := c.step(context.Background(), mx, cur)
		ssm.rememberVisitedURLs(q)
		redirects, _ := ssm.redirects(mx)
		tkoe.TestKeys.Steps = append(tkoe.TestKeys.Steps, ssm)
		q.Append(redirects...)
		c.logger.Infof("🪀 work queue: %s", q.String())
	}
	c.Output <- tkoe
}

// rememberVisitedURLs inspects all the URLs visited by the
// probe and stores them into the redirect deque.
func (ssm *SingleStepMeasurement) rememberVisitedURLs(q *measurex.URLRedirectDeque) {
	if ssm.ProbeInitial != nil {
		q.RememberVisitedURLs(ssm.ProbeInitial.Endpoint)
	}
	q.RememberVisitedURLs(ssm.ProbeAdditional)
}

// redirects computes all the redirects from all the results
// that are stored inside the test keys.
func (ssm *SingleStepMeasurement) redirects(mx *measurex.Measurer) (o []*measurex.URLMeasurement, v bool) {
	if ssm.ProbeInitial != nil {
		r, _ := mx.Redirects(ssm.ProbeInitial.Endpoint, ssm.ProbeInitial.Options)
		o = append(o, r...)
	}
	if ssm.TH != nil {
		r, _ := mx.Redirects(ssm.TH.Endpoint, ssm.ProbeInitial.Options)
		o = append(o, r...)
	}
	r, _ := mx.Redirects(ssm.ProbeAdditional, ssm.ProbeInitial.Options)
	o = append(o, r...)
	return o, len(o) > 0
}

// defaultResolvers returns the default resolvers.
func defaultResolvers() []*measurex.DNSResolverInfo {
	// TODO(bassosimone): randomize the resolvers we use...
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
	mx *measurex.Measurer, cur *measurex.URLMeasurement) *SingleStepMeasurement {
	c.dnsLookup(ctx, mx, cur)
	ssm := newSingleStepMeasurement(cur)
	thc := c.th(ctx, cur)
	c.measureDiscoveredEndpoints(ctx, mx, cur)
	c.measureAltSvcEndpoints(ctx, mx, cur)
	maybeTH := <-thc
	if maybeTH.Err == nil {
		// Implementation note: the purpose of this "import" is to have
		// timing and IDs compatible with our measurements.
		c.logger.Info("🚧️ [th] importing the TH measurements")
		ssm.TH = c.importTHMeasurement(mx, maybeTH.Resp, cur)
	}
	c.measureAdditionalEndpoints(ctx, mx, ssm)
	c.logger.Infof("🔬 analyzing the collected results")
	ssm.Analysis.DNS = ssm.dnsAnalysis(mx, c.logger)
	ssm.Analysis.Endpoint = ssm.endpointAnalysis(mx, c.logger)
	ssm.Analysis.URL = ssm.urlAnalysis(mx, c.logger)
	// TODO(bassosimone): run follow-up experiments
	return ssm
}

func (c *Client) dnsLookup(ctx context.Context,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	c.logger.Info("📡 [initial] resolving the domain name using all resolvers")
	dnsPlan := cur.NewDNSLookupPlan(c.resolvers)
	for m := range mx.DNSLookups(ctx, dnsPlan) {
		cur.DNS = append(cur.DNS, m)
	}
}

func (c *Client) measureDiscoveredEndpoints(ctx context.Context,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	c.logger.Info("📡 [initial] measuring endpoints discovered using the DNS")
	plan, _ := cur.NewEndpointPlan(c.logger, 0)
	for m := range mx.MeasureEndpoints(ctx, plan...) {
		cur.Endpoint = append(cur.Endpoint, m)
	}
}

func (c *Client) measureAltSvcEndpoints(ctx context.Context,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	c.logger.Info("📡 [initial] measuring extra endpoints discovered using Alt-Svc (if any)")
	epntPlan, _ := cur.NewEndpointPlan(c.logger, measurex.EndpointPlanningOnlyHTTP3)
	for m := range mx.MeasureEndpoints(ctx, epntPlan...) {
		cur.Endpoint = append(cur.Endpoint, m)
	}
}

// importTHMeasurement returns a copy of the input measurement with
// adjusted IDs (related to the measurer) and times.
func (c *Client) importTHMeasurement(mx *measurex.Measurer, in *THResponse,
	cur *measurex.URLMeasurement) (out *THResponseWithID) {
	out = &THResponseWithID{
		id:       cur.ID,
		DNS:      []*measurex.DNSLookupMeasurement{},
		Endpoint: []*measurex.EndpointMeasurement{},
	}
	now := time.Now()
	for _, e := range in.DNS {
		out.DNS = append(out.DNS, &measurex.DNSLookupMeasurement{
			ID:               mx.NextID(),
			URLMeasurementID: cur.ID,
			Lookup: &archival.FlatDNSLookupEvent{
				ALPNs:           e.ALPNs(),
				Addresses:       e.Addresses(),
				Domain:          e.Domain(),
				Failure:         e.Failure(),
				Finished:        now,
				LookupType:      e.LookupType(),
				ResolverAddress: e.ResolverAddress(),
				ResolverNetwork: e.ResolverNetwork(),
				Started:         now,
			},
			RoundTrip: []*archival.FlatDNSRoundTripEvent{},
		})
	}
	for _, e := range in.Endpoint {
		out.Endpoint = append(out.Endpoint, &measurex.EndpointMeasurement{
			ID:               mx.NextID(),
			URLMeasurementID: cur.ID,
			URL:              e.URL,
			Network:          e.Network,
			Address:          e.Address,
			OrigCookies:      e.OrigCookies,
			Failure:          e.Failure,
			FailedOperation:  e.FailedOperation,
			NewCookies:       e.NewCookies,
			Location:         e.Location,
			NetworkEvent:     []*archival.FlatNetworkEvent{},
			TCPConnect:       nil,
			QUICTLSHandshake: nil,
			HTTPRoundTrip:    c.importHTTPRoundTripEvent(now, e.HTTPRoundTrip),
		})
	}
	return
}

func (c *Client) importHTTPRoundTripEvent(now time.Time,
	in *archival.FlatHTTPRoundTripEvent) (o *archival.FlatHTTPRoundTripEvent) {
	if in != nil {
		o = &archival.FlatHTTPRoundTripEvent{
			Failure:                 in.Failure,
			Finished:                now,
			Method:                  in.Method,
			RequestHeaders:          in.RequestHeaders,
			ResponseBody:            nil,
			ResponseBodyIsTruncated: in.ResponseBodyIsTruncated,
			ResponseBodyLength:      in.ResponseBodyLength,
			ResponseHeaders:         in.ResponseHeaders,
			Started:                 now,
			StatusCode:              in.StatusCode,
			Transport:               in.Transport,
			URL:                     in.URL,
		}
	}
	return
}

// URLAddressList builds a []*URLAddress from the TH measurement. In case
// the TH measurement is nil or there are no suitable addresses, the return
// value is a nil list and false. Otherwise, a valid list and true.
func (thm *THResponseWithID) URLAddressList() (o []*measurex.URLAddress, v bool) {
	if thm != nil {
		o, v = measurex.NewURLAddressList(thm.id, thm.DNS, thm.Endpoint)
	}
	return
}

func (c *Client) measureAdditionalEndpoints(ctx context.Context,
	mx *measurex.Measurer, ssm *SingleStepMeasurement) {
	c.logger.Info("📡 [additional] measuring extra endpoints discovered by the TH (if any)")
	addrslist, _ := c.expandProbeKnowledgeWithTHData(mx, ssm.ProbeInitial, ssm.TH)
	plan, _ := ssm.ProbeInitial.NewEndpointPlanWithAddressList(c.logger, addrslist, 0)
	for m := range mx.MeasureEndpoints(ctx, plan...) {
		ssm.ProbeAdditional = append(ssm.ProbeAdditional, m)
	}
}

// expandProbeKnowledgeWithTHData returns a list of URL addresses that extends
// the original set of facts known by the probe by adding:
//
// 1. information about HTTP3 support for hosts;
//
// 2. new IP addresses previously unknown to the probe.
//
// If the return value is (nil, false), it means we could not discover any
// new information. Otherwise, we return a valid list and true.
func (c *Client) expandProbeKnowledgeWithTHData(mx *measurex.Measurer,
	probem *measurex.URLMeasurement, thm *THResponseWithID) ([]*measurex.URLAddress, bool) {
	// 1. gather the lists for the probe and the th
	pal, _ := probem.URLAddressList()
	thal, _ := thm.URLAddressList()
	// 2. build a map of the addresses known by the probe.
	pam := make(map[string]*measurex.URLAddress)
	for _, e := range pal {
		pam[e.Address] = e
	}
	// 3. expand probe's knowledge using the TH list.
	var (
		o    []*measurex.URLAddress
		uniq = make(map[string]bool)
	)
	for _, the := range thal {
		if p, found := pam[the.Address]; found {
			// 3.1. if the test helper knows that a given IP address also known by
			// the probe supports HTTP3 and the probe does not, we add such an address.
			if (p.Flags & measurex.URLAddressAlreadyTestedHTTP3) != 0 {
				continue
			}
			if (the.Flags & measurex.URLAddressAlreadyTestedHTTP3) != 0 {
				mx.Logger.Infof("🙌 the TH told us that %s supports HTTP3", the.Address)
				p.Flags |= measurex.URLAddressSupportsHTTP3
				o = append(o, p)
			}
			continue
		}
		// 3.2. otherwise, if this IP address is unknown to the probe, we're
		// going to add such an address to the probe's list.
		if _, found := uniq[the.Address]; found {
			continue
		}
		o = append(o, &measurex.URLAddress{
			URLMeasurementID: the.URLMeasurementID,
			Address:          the.Address,
			Flags:            (the.Flags & measurex.URLAddressSupportsHTTP3),
		})
		mx.Logger.Infof("🙌 the TH told us about new %s address for domain", the.Address)
		uniq[the.Address] = true
	}
	return o, len(o) > 0
}
