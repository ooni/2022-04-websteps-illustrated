package websteps

//
// Client
//
// This file contains the websteps client.
//

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/dnsping"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// TestKeys contains the experiment test keys.
type TestKeys struct {
	// URL is the URL this measurement refers to.
	URL string

	// Steps contains all the steps.
	Steps []*SingleStepMeasurement

	// Bodies contains information about the bodies.
	Bodies *HashingBodies

	// Flags contains the analysis flags.
	Flags int64
}

// ArchivalTestKeys contains the archival test keys.
type ArchivalTestKeys struct {
	URL    string                           `json:"url"`
	Steps  []*ArchivalSingleStepMeasurement `json:"steps"`
	Bodies *HashingBodies                   `json:"bodies"`
	Flags  int64                            `json:"flags"`
}

// ToArchival converts TestKeys to the archival data format.
func (tk *TestKeys) ToArchival(begin time.Time) (out *ArchivalTestKeys) {
	out = &ArchivalTestKeys{
		URL:    tk.URL,
		Steps:  []*ArchivalSingleStepMeasurement{}, // later
		Bodies: tk.Bodies,
		Flags:  tk.Flags,
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

	// dialerCleartext is the cleartext dialer to use.
	dialerCleartext model.Dialer

	// dialerTLS is the TLS dialer to use.
	dialerTLS model.TLSDialer

	// logger is the MANDATORY logger to use.
	logger model.Logger

	// options contains measurex options.
	options *measurex.Options

	// resolvers contains the MANDATORY resolvers to use.
	resolvers []*measurex.DNSResolverInfo

	// thURL is the base URL of the test helper.
	thURL string
}

// THClient is a client for communicating with the test helper.
type THClient interface {
	// THRequestAsync performs an async TH request posting the result on the out channel.
	THRequestAsync(ctx context.Context, thReq *THRequest, out chan<- *THResponseOrError)
}

// NewTHClient creates a new client that does not perform measurements
// and is only suitable for speaking with the TH.
func NewTHClient(logger model.Logger, dialer model.Dialer,
	tlsDialer model.TLSDialer, thURL string) THClient {
	return newClient(context.Background(), logger, dialer,
		tlsDialer, thURL, false, &measurex.Options{})
}

// StartClient starts a new websteps client instance in a background goroutine
// and returns the client instance to submit and collect measurements.
func StartClient(ctx context.Context, logger model.Logger, dialer model.Dialer,
	tlsDialer model.TLSDialer, thURL string, clientOptions *measurex.Options) *Client {
	return newClient(ctx, logger, dialer, tlsDialer, thURL, true, clientOptions)
}

// newClient implements NewTHClient and StartClient.
func newClient(ctx context.Context, logger model.Logger, dialer model.Dialer,
	tlsDialer model.TLSDialer, thURL string, startBackgroundWorker bool,
	clientOptions *measurex.Options) *Client {
	clnt := &Client{
		Input:           make(chan string),
		Output:          make(chan *TestKeysOrError),
		dialerCleartext: dialer,
		dialerTLS:       tlsDialer,
		logger:          logger,
		options:         clientOptions,
		resolvers:       defaultResolvers(),
		thURL:           thURL,
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
	mx.Options = c.options // ensure we use user-selected options (if any)
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
	cache := newStepsCache()
	for ctx.Err() == nil { // know that a user has requested to stop
		cur, found := q.PopLeft()
		if !found {
			// TODO(bassosimone): here we should record whether
			// we are leaving with an empty queue or not. We may
			// also leave when we reach the max crawler depth.
			break
		}
		c.logger.Infof("📌 depth=%d; crawling %s", q.Depth(), cur.URL.String())
		// Implementation note: here we use a background context for the
		// measurement step because we don't want to interrupt web measurements
		// midway. We'll stop when we enter into the next iteration.
		ssm := c.step(context.Background(), cache, mx, cur)
		cache.update(ssm)
		ssm.rememberVisitedURLs(q)
		redirects, _ := ssm.redirects(mx)
		tkoe.TestKeys.Steps = append(tkoe.TestKeys.Steps, ssm)
		q.Append(redirects...)
		c.logger.Infof("🪀 work queue: %s", q.String())
	}
	tkoe.TestKeys.Bodies = tkoe.TestKeys.buildHashingBodies(mx)
	tkoe.TestKeys.finalReprocessingAndLogging(c.logger)  // depends on hashes
	tkoe.TestKeys.Flags = tkoe.TestKeys.aggregateFlags() // depends on reprocessing
	c.Output <- tkoe
}

// aggregateFlags produces the aggregate flags for each SingleStep
// and then aggregates each SingleStep into TestKeys flags.
func (tk *TestKeys) aggregateFlags() (flags int64) {
	for _, step := range tk.Steps {
		step.Flags = step.aggregateFlags()
		flags |= step.Flags
	}
	return flags
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

// clientCandidateResolversA returns the candidate resolvers with an A address.
func clientCandidateResolversA() []*measurex.DNSResolverInfo {
	return []*measurex.DNSResolverInfo{{
		Network: "udp",
		Address: "8.8.8.8:53",
	}, {
		Network: "udp",
		Address: "8.8.4.4:53",
	}, {
		Network: "udp",
		Address: "1.1.1.1:53",
	}, {
		Network: "udp",
		Address: "1.0.0.1:53",
	}, {
		Network: "udp",
		Address: "9.9.9.9:53",
	}, {
		Network: "udp",
		Address: "149.112.112.112:53",
	}}
}

// clientCandidateResolversAAAA returns the candidate resolvers with an AAAA address.
func clientCandidateResolversAAAA() []*measurex.DNSResolverInfo {
	return []*measurex.DNSResolverInfo{{
		Network: "udp",
		Address: "[2001:4860:4860::8844]:53",
	}, {
		Network: "udp",
		Address: "[2001:4860:4860::8888]:53",
	}, {
		Network: "udp",
		Address: "[2606:4700:4700::1001]:53",
	}, {
		Network: "udp",
		Address: "[2606:4700:4700::1111]:53",
	}, {
		Network: "udp",
		Address: "[2620:fe::fe]:53",
	}, {
		Network: "udp",
		Address: "[2620:fe::9]:53",
	}}
}

// shuffleResolversList shuffles a list of resolvers using a rand.
func shuffleResolversList(r *rand.Rand, list []*measurex.DNSResolverInfo) {
	r.Shuffle(len(list), func(i, j int) {
		list[i], list[j] = list[j], list[i]
	})
}

// defaultResolvers returns the default resolvers.
func defaultResolvers() (out []*measurex.DNSResolverInfo) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	craaaa := clientCandidateResolversAAAA()
	shuffleResolversList(r, craaaa)
	if len(craaaa) > 0 {
		out = append(out, craaaa[0])
	}
	cra := clientCandidateResolversA()
	shuffleResolversList(r, cra)
	if len(cra) > 0 {
		out = append(out, cra[0])
	}
	out = append(out, &measurex.DNSResolverInfo{
		Network: "system",
		Address: "",
	})
	return out
}

// step performs a single step.
func (c *Client) step(ctx context.Context, cache *stepsCache,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) *SingleStepMeasurement {
	c.dnsLookup(ctx, cache, mx, cur)
	dc := c.dnsPingFollowUp(ctx, mx, cur)
	ssm := newSingleStepMeasurement(cur)
	thc := c.th(ctx, cur)
	c.measureDiscoveredEndpoints(ctx, cache, mx, cur)
	c.measureAltSvcEndpoints(ctx, mx, cur)
	maybeTH := c.waitForTHC(thc)
	if maybeTH.Err == nil {
		// Implementation note: the purpose of this "import" is to have
		// timing and IDs compatible with our measurements.
		c.logger.Info("🚧️ [th] importing TH measurements")
		ssm.TH = c.importTHMeasurement(mx, maybeTH.Resp, cur)
	}
	ssm.DNSPing = c.waitForDNSPing(dc)
	c.measureAdditionalEndpoints(ctx, mx, ssm)
	c.logger.Infof("🔬 analyzing the collected results")
	ssm.Analysis.DNS = ssm.dnsAnalysis(mx, c.logger)
	ssm.Analysis.Endpoint = ssm.endpointAnalysis(mx, c.logger)
	// TODO(bassosimone): run follow-up experiments
	return ssm
}

func (c *Client) waitForTHC(thc <-chan *THResponseOrError) *THResponseOrError {
	ol := measurex.NewOperationLogger(c.logger, "waiting for TH to complete")
	out := <-thc
	ol.Stop(out.Err)
	return out
}

func (c *Client) waitForDNSPing(dc <-chan *dnsping.Result) *dnsping.Result {
	ol := measurex.NewOperationLogger(c.logger, "wait on dnsping if it was started")
	out := <-dc
	ol.Stop(nil)
	return out
}

func (c *Client) dnsLookup(ctx context.Context, cache *stepsCache,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	dnsv, found := cache.dnsLookup(mx, cur.ID, cur.Domain())
	if found {
		c.logger.Infof("📡 [initial] domain %s already in dnscache", cur.Domain())
		cur.DNS = append(cur.DNS, dnsv)
		return
	}
	c.logger.Infof("📡 [initial] resolving %s name using all resolvers", cur.Domain())
	dnsPlan := cur.NewDNSLookupPlan(c.resolvers)
	for m := range mx.DNSLookups(ctx, dnsPlan) {
		cur.DNS = append(cur.DNS, m)
	}
}

func (c *Client) measureDiscoveredEndpoints(ctx context.Context, cache *stepsCache,
	mx *measurex.Measurer, cur *measurex.URLMeasurement) {
	c.logger.Info("📡 [initial] measuring endpoints discovered using the DNS")
	ual, _ := cur.URLAddressList()
	// Rewrite the current URLAddressList to ensure that IP addresses we've already
	// used, even if with different domains, end up at the beginning. A test case
	// for this is http://torproject.org, which has four A and four AAAA addrs. In the
	// default configuration, we want the redirect to https://www.torproject.org to
	// use the same two A and two AAAA it used in the first step.
	ual = cache.prioritizeKnownAddrs(ual)
	plan, _ := cur.NewEndpointPlanWithAddressList(c.logger, ual, 0)
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
			ResponseBodyTLSH:        in.ResponseBodyTLSH,
			ResponseHeaders:         in.ResponseHeaders,
			Started:                 now,
			StatusCode:              in.StatusCode,
			Transport:               in.Transport,
			URL:                     in.URL,
		}
	}
	return
}

// URLAddressList builds a []*URLAddress from the TH measurement. The
// domain argument is the domain of the URL we're measuring. In case
// the TH measurement is nil or there are no suitable addresses, the return
// value is a nil list and false. Otherwise, a valid list and true.
func (thm *THResponseWithID) URLAddressList(domain string) (o []*measurex.URLAddress, v bool) {
	if thm != nil {
		o, v = measurex.NewURLAddressList(thm.id, domain, thm.DNS, thm.Endpoint)
	}
	return
}

func (c *Client) measureAdditionalEndpoints(ctx context.Context,
	mx *measurex.Measurer, ssm *SingleStepMeasurement) {
	c.logger.Info("📡 [additional] looking for new endpoints in TH/dnsping results")
	addrslist, _ := c.expandProbeKnowledge(mx, ssm)
	plan, _ := ssm.ProbeInitial.NewEndpointPlanWithAddressList(c.logger, addrslist, 0)
	if len(plan) > 0 {
		c.logger.Info("📡 [additional] measuring newly discovered endpoints")
	}
	for m := range mx.MeasureEndpoints(ctx, plan...) {
		ssm.ProbeAdditional = append(ssm.ProbeAdditional, m)
	}
}

// expandProbeKnowledge returns a list of URL addresses that extends
// the original list known to the probe by:
//
// 1. adding information about HTTP3 support to each address known to
// the probe for which the probe didn't know about HTTP3 support;
//
// 2. appending at the end of the list any address that was discovered
// using TH/dnsping and the probe didn't previously know.
//
// The returned list will always containg everything the probe already
// knew at the beginning, following by newly discovered addresses. This
// sorting allows us to prevent the probe from testing more than the
// configured maximum number of IP addresses per family.
//
// The boolean returned value is true if we have at least one IP address
// to return and false otherwise. Beware that returning a non-empty
// list doesn't imply that the probe will end up testing it. Limitations
// on the maximum number of addresses per family apply.
func (c *Client) expandProbeKnowledge(
	mx *measurex.Measurer, ssm *SingleStepMeasurement) ([]*measurex.URLAddress, bool) {
	// 1. gather the lists for the probe and the th
	pal, _ := ssm.probeInitialURLAddressList()
	thal, _ := ssm.testHelperOrDNSPingURLAddressList()
	// 2. merge the two lists making sure that we specify the probe
	// list before the other lists.
	o := measurex.MergeURLAddressListStable(pal, thal)
	// 3. compute the diff between the new list and the probe's
	// list, so we can log the changes.
	diff := measurex.NewURLAddressListDiff(o, pal)
	for _, e := range diff.ModifiedFlags {
		if (e.Flags & measurex.URLAddressSupportsHTTP3) != 0 {
			mx.Logger.Infof("🙌 discovered that %s supports HTTP3", e.Address)
		}
	}
	for _, e := range diff.NewEntries {
		mx.Logger.Infof("🙌 discovered new %s address for %s", e.Address, e.Domain)
	}
	return o, len(o) > 0
}

func (ssm *SingleStepMeasurement) probeInitialURLAddressList() (
	out []*measurex.URLAddress, good bool) {
	if ssm.ProbeInitial != nil {
		return ssm.ProbeInitial.URLAddressList()
	}
	return nil, false
}

func (ssm *SingleStepMeasurement) testHelperOrDNSPingURLAddressList() (
	out []*measurex.URLAddress, good bool) {
	if ssm.TH != nil {
		data, _ := ssm.TH.URLAddressList(ssm.ProbeInitialDomain())
		out = append(out, data...)
	}
	if ssm.DNSPing != nil {
		id := ssm.ProbeInitialURLMeasurementID()
		// Note: we're filtering by domain here because potentially the
		// dnsping could test multiple domains together, so we need to be
		// sure that we only include the domain we're retesting
		data, _ := ssm.DNSPing.URLAddressList(id, ssm.ProbeInitialDomain())
		out = append(out, data...)
	}
	return out, len(out) > 0
}
