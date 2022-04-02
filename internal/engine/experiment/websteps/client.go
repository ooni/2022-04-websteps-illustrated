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
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// TestKeys contains the experiment test keys.
type TestKeys struct {
	// URL is the URL this measurement refers to.
	URL string

	// Steps contains all the steps.
	Steps []*SingleStepMeasurement

	// Flags contains the analysis flags.
	Flags int64
}

// TestKeysOrError contains either test keys or an error.
type TestKeysOrError struct {
	// Err is the error that occurred.
	Err error

	// TestKeys are the test keys.
	TestKeys *TestKeys
}

// Client is the websteps client. You cannot create an instance of
// this struct manually, because the zero type does not work out
// of the box. You MUST use the NewClient constructor to construct
// a valid Client and then you can modify the public fields. You
// MUST do that before starting the client loop.
type Client struct {
	// Input is the MANDATORY channel for receiving Input.
	Input chan string

	// MeasurerFactory is the OPTIONAL factory for creating
	// new measurer instances. If you set this field, you MUST
	// set it before starting any background worker.
	MeasurerFactory MeasurerFactory

	// NewDNSPingEngine is the MANDATORY factory for creating
	// new instances of the dnsping engine. You should set this
	// field before starting any background worker. You may
	// want to use this field for caching dnsping results.
	NewDNSPingEngine func(
		idgen dnsping.IDGenerator, queryTimeout time.Duration) dnsping.AbstractEngine

	// Output is the MANDATORY channel for emitting measurements.
	Output chan *TestKeysOrError

	// Resolvers contains the MANDATORY Resolvers to use.
	Resolvers []*measurex.DNSResolverInfo

	// THMeasurementObserver is an OPTIONAL hook allowing
	// the user to view/store the response from the TH.
	//
	// You MUST NOT modify the measurement. Doing that is
	// most likely going to result in a data race.
	THMeasurementObserver func(m *THResponse)

	// dialerCleartext is the cleartext dialer to use.
	dialerCleartext model.Dialer

	// dialerTLS is the TLS dialer to use.
	dialerTLS model.TLSDialer

	// options contains measurex options.
	options *measurex.Options

	// thURL is the base URL of the test helper.
	thURL string
}

// THClient is a client for communicating with the test helper.
type THClient interface {
	// THRequestAsync performs an async TH request posting the result on the out channel.
	THRequestAsync(ctx context.Context, thReq *THRequest, out chan<- *THResponseOrError)

	// THRequest performs a sync TH request.
	THRequest(ctx context.Context, req *THRequest) (*THResponse, error)
}

// NewTHClient creates a new client for communicating with the TH.
func NewTHClient(dialer model.Dialer, tlsDialer model.TLSDialer, thURL string) THClient {
	return NewClient(dialer, tlsDialer, thURL, &measurex.Options{})
}

// NewTHClient with default settings creates a new THClient using default settings.
func NewTHClientWithDefaultSettings(thURL string) THClient {
	return NewTHClient(nil, nil, thURL)
}

// NewClient creates a new Client instance.
func NewClient(dialer model.Dialer, tlsDialer model.TLSDialer, thURL string,
	clientOptions *measurex.Options) *Client {
	return &Client{
		Input:           make(chan string),
		MeasurerFactory: nil, // meaning that we'll use a default factory
		NewDNSPingEngine: func(
			idgen dnsping.IDGenerator, queryTimeout time.Duration) dnsping.AbstractEngine {
			return dnsping.NewEngine(idgen, queryTimeout)
		},
		Output:          make(chan *TestKeysOrError),
		dialerCleartext: dialer,
		dialerTLS:       tlsDialer,
		options:         clientOptions,
		Resolvers:       defaultResolvers(),
		thURL:           thURL,
	}
}

const (
	// LoopFlagGreedy makes websteps stop following redirects as soon
	// as it has found signs of censorship. This flag allows a user to
	// control whether to prioritize depth or breadth.
	LoopFlagGreedy = 1 << iota
)

// Loop is the client Loop.
func (c *Client) Loop(ctx context.Context, flags int64) {
	for input := range c.Input {
		// Implementation note: with a cancelled context, continue to
		// loop and drain the input channel. The client will eventually
		// notice the context is cancelled and close our input.
		if ctx.Err() == nil {
			c.steps(ctx, input, flags)
		}
	}
	close(c.Output)
}

func (c *Client) newMeasurer(options *measurex.Options) (measurex.AbstractMeasurer, error) {
	if c.MeasurerFactory != nil {
		return c.MeasurerFactory(options)
	}
	library := measurex.NewDefaultLibrary()
	return measurex.NewMeasurerWithOptions(library, c.options), nil
}

// steps performs all the steps.
func (c *Client) steps(ctx context.Context, input string, flags int64) {
	mx, err := c.newMeasurer(c.options)
	if err != nil {
		logcat.Bugf("[websteps] cannot create a new measurer: %s", err.Error())
		c.Output <- &TestKeysOrError{
			Err:      fmt.Errorf("cannot create measurer %s: %w", input, err),
			TestKeys: nil,
		}
		return
	}
	initial, err := mx.NewURLMeasurement(input)
	if err != nil {
		logcat.Shrugf("[websteps] cannot parse input as URL: %s", err.Error())
		c.Output <- &TestKeysOrError{
			Err:      fmt.Errorf("cannot parse %s: %w", input, err),
			TestKeys: nil,
		}
		return
	}
	q := mx.NewURLRedirectDeque()
	logcat.NewInputf("you asked me to measure '%s' and up to %d redirects... let's go!", input, q.MaxDepth())
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
		cur, err := q.PopLeft()
		if err != nil {
			logcat.Noticef("crawler: %s", err.Error())
			break
		}
		logcat.Stepf("now measuring '%s'", cur.URL.String())
		// Implementation note: here we use a background context for the
		// measurement step because we don't want to interrupt web measurements
		// midway. We'll stop when we enter into the next iteration.
		ssm := c.step(context.Background(), cache, mx, cur)
		cache.update(ssm)
		ssm.rememberVisitedURLs(q)
		redirects, _ := ssm.redirects(mx)
		tkoe.TestKeys.Steps = append(tkoe.TestKeys.Steps, ssm)
		q.Append(redirects...)
		ssm.Flags = ssm.aggregateFlags()
		if AnalysisFlagsContainAnomalies(ssm.Flags) && (flags&LoopFlagGreedy) != 0 {
			logcat.Notice("greedy mode: stop as soon as we see anomalies")
			break
		}
		logcat.Infof("work queue: %s", q.String())
	}
	tkoe.TestKeys.Flags = tkoe.TestKeys.aggregateFlags()
	tkoe.TestKeys.finalLogging() // must be last
	c.Output <- tkoe
}

// aggregateFlags produces the aggregate flags for each SingleStep
// and then aggregates each SingleStep into TestKeys flags.
func (tk *TestKeys) aggregateFlags() (flags int64) {
	for _, step := range tk.Steps {
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
func (ssm *SingleStepMeasurement) redirects(
	mx measurex.AbstractMeasurer) (o []*measurex.URLMeasurement, v bool) {
	if ssm.ProbeInitial == nil {
		return nil, false
	}
	r1, _ := mx.Redirects(ssm.ProbeInitial.Endpoint, ssm.ProbeInitial.Options)
	o = append(o, r1...)
	if ssm.TH != nil {
		r2, _ := mx.Redirects(ssm.TH.Endpoint, ssm.ProbeInitial.Options)
		o = append(o, r2...)
	}
	r3, _ := mx.Redirects(ssm.ProbeAdditional, ssm.ProbeInitial.Options)
	o = append(o, r3...)
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

// PredictableDNSResolvers always returns the same list of DNS
// resolvers. It's not recommended to use this function when running
// websteps in production. However, having predictable resolvers
// reduces the effort required to build a probe cache. Without forcing
// predictable resolvers, every websteps run possibly picks different
// random resolvers. Running websteps once does not therefore guarantee
// that you can reuse the cache produced by such a single run from
// another location to replicate the same measurement that generated
// the cache. On the contrary, forcing predictable resolvers to be
// Client.Resolvers gives you that guarantee.
func PredictableDNSResolvers() []*measurex.DNSResolverInfo {
	return []*measurex.DNSResolverInfo{{
		Network: "udp",
		Address: "8.8.8.8:53",
	}, {
		Network: "udp",
		Address: "[2001:4860:4860::8888]:53",
	}, {
		Network: "system",
		Address: "",
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
	mx measurex.AbstractMeasurer, cur *measurex.URLMeasurement) *SingleStepMeasurement {
	c.dnsLookup(ctx, cache, mx, cur)
	dc, pingRunning := c.dnsPingFollowUp(ctx, mx, cur)
	ssm := newSingleStepMeasurement(cur)
	epplan := c.newEndpointPlan(cur, cache)
	thc := c.th(ctx, cur, epplan)
	c.measureDiscoveredEndpoints(ctx, mx, cur, epplan)
	c.measureAltSvcEndpoints(ctx, mx, cur)
	logcat.Substep("obtaining TH's measurements results")
	maybeTH := c.waitForTHC(thc)
	if maybeTH.Err == nil {
		// Implementation note: the purpose of this "import" is to have
		// timing and IDs compatible with our measurements.
		ssm.TH = c.importTHMeasurement(mx, maybeTH.Resp, cur)
		if c.THMeasurementObserver != nil {
			c.THMeasurementObserver(ssm.TH)
		}
	}
	ssm.DNSPing = c.waitForDNSPing(dc, pingRunning)
	c.measureAdditionalEndpoints(ctx, mx, ssm)
	ssm.Analysis.DNS = ssm.dnsAnalysis(mx)
	ssm.Analysis.Endpoint = ssm.endpointAnalysis(mx)
	ssm.Analysis.TH = ssm.analyzeTHResults(mx)
	// TODO(bassosimone): run follow-up experiments (e.g., SNI blocking)
	return ssm
}

func (c *Client) waitForTHC(thc <-chan *THResponseOrError) *THResponseOrError {
	ol := measurex.NewOperationLogger("waiting for TH to complete")
	out := <-thc
	ol.Stop(out.Err)
	return out
}

func (c *Client) waitForDNSPing(dc <-chan *dnsping.Result, pingRunning bool) *dnsping.Result {
	if !pingRunning {
		return nil
	}
	logcat.Substep("obtaining dnsping measurements results")
	ol := measurex.NewOperationLogger("waiting for dnsping to complete")
	out := <-dc
	ol.Stop(nil)
	return out
}

func (c *Client) dnsLookup(ctx context.Context, cache *stepsCache,
	mx measurex.AbstractMeasurer, cur *measurex.URLMeasurement) {
	dnsv, found := cache.dnsLookup(mx, cur.ID, cur.Domain())
	if found {
		logcat.Substepf("no need to resolve; I already know '%s' IP addresses", cur.Domain())
		cur.DNS = append(cur.DNS, dnsv)
		return
	}
	logcat.Substepf("resolving '%s' to IP addresses", cur.Domain())
	const flags = 0 // no extra queries
	dnsPlans := cur.NewDNSLookupPlans(flags, c.Resolvers...)
	for m := range mx.DNSLookups(ctx, dnsPlans...) {
		cur.DNS = append(cur.DNS, m)
	}
}

// newEndpointPlan computes the endpoint plan taking into account the
// IP addresses we have just resolved and ensuring that we stick to the known
// ones, so subsequent redirects use consistent addresses.
func (c *Client) newEndpointPlan(
	cur *measurex.URLMeasurement, cache *stepsCache) []*measurex.EndpointPlan {
	ual, _ := cur.URLAddressList()
	if len(ual) <= 0 {
		logcat.Shrugf("unfortunately it seems I did not discover any IP address")
		return []*measurex.EndpointPlan{}
	}
	logcat.Noticef("discovered these IP addresses: %s", measurex.URLAddressListToString(ual))
	// Rewrite the current URLAddressList to ensure that IP addresses we've already
	// used, even if with different domains, end up at the beginning. A test case
	// for this is http://torproject.org, which has four A and four AAAA addrs. In the
	// default configuration, we want the redirect to https://www.torproject.org to
	// use the same two A and two AAAA it used in the first step.
	ual = cache.prioritizeKnownAddrs(ual)
	plan, _ := cur.NewEndpointPlanWithAddressList(ual, 0)
	return plan
}

func (c *Client) measureDiscoveredEndpoints(ctx context.Context,
	mx measurex.AbstractMeasurer, cur *measurex.URLMeasurement, plan []*measurex.EndpointPlan) {
	if len(plan) <= 0 {
		logcat.Shrugf("unfortunately, there are no valid endpoints to test here")
		return
	}
	logcat.Substepf("now testing %d HTTP/HTTPS/HTTP3 endpoints deriving from the discovered IP addresses", len(plan))
	for m := range mx.MeasureEndpoints(ctx, plan...) {
		cur.Endpoint = append(cur.Endpoint, m)
	}
}

func (c *Client) measureAltSvcEndpoints(ctx context.Context,
	mx measurex.AbstractMeasurer, cur *measurex.URLMeasurement) {
	epntPlan, _ := cur.NewEndpointPlan(measurex.EndpointPlanningOnlyHTTP3)
	if len(epntPlan) <= 0 {
		return
	}
	for m := range mx.MeasureEndpoints(ctx, epntPlan...) {
		cur.Endpoint = append(cur.Endpoint, m)
	}
}

// importTHMeasurement returns a copy of the input measurement with
// adjusted IDs (related to the measurer) and times.
func (c *Client) importTHMeasurement(mx measurex.AbstractMeasurer, in *THResponse,
	cur *measurex.URLMeasurement) (out *THResponse) {
	out = &THResponse{
		URLMeasurementID: cur.ID,
		DNS:              []*measurex.DNSLookupMeasurement{},
		Endpoint:         []*measurex.EndpointMeasurement{},
	}
	now := time.Now()
	for _, e := range in.DNS {
		dns := &measurex.DNSLookupMeasurement{
			ID:               mx.NextID(),
			URLMeasurementID: cur.ID,
			ReverseAddress:   e.ReverseAddress,
			Lookup: &archival.FlatDNSLookupEvent{
				ALPNs:           e.ALPNs(),
				Addresses:       e.Addresses(),
				CNAME:           e.CNAME(),
				Domain:          e.Domain(),
				Failure:         e.Failure(),
				Finished:        now,
				LookupType:      e.LookupType(),
				NS:              e.NS(),
				PTRs:            e.PTRs(),
				ResolverAddress: e.ResolverAddress(),
				ResolverNetwork: e.ResolverNetwork(),
				Started:         now,
			},
			RoundTrip: c.importDNSRoundTripEvent(now, e.RoundTrip),
		}
		logcat.Noticef("import %s... %s", dns.Describe(), archival.FlatFailureToStringOrOK(dns.Failure()))
		out.DNS = append(out.DNS, dns)
	}
	for _, e := range in.Endpoint {
		nem := &measurex.EndpointMeasurement{
			ID:               mx.NextID(),
			URLMeasurementID: cur.ID,
			URL:              e.URL,
			Network:          e.Network,
			Address:          e.Address,
			Options:          e.Options,
			OrigCookies:      e.OrigCookies,
			Finished:         now,
			Failure:          e.Failure,
			FailedOperation:  e.FailedOperation,
			NewCookies:       e.NewCookies,
			Location:         e.Location,
			HTTPTitle:        e.HTTPTitle,
			NetworkEvent:     []*archival.FlatNetworkEvent{},
			TCPConnect:       nil,
			QUICTLSHandshake: nil,
			HTTPRoundTrip:    c.importHTTPRoundTripEvent(now, e.HTTPRoundTrip),
		}
		logcat.Noticef("import %s... %s", nem.Describe(), archival.FlatFailureToStringOrOK(nem.Failure))
		out.Endpoint = append(out.Endpoint, nem)
	}
	return
}

func (c *Client) importDNSRoundTripEvent(now time.Time,
	input []*archival.FlatDNSRoundTripEvent) (out []*archival.FlatDNSRoundTripEvent) {
	for _, e := range input {
		out = append(out, &archival.FlatDNSRoundTripEvent{
			ResolverAddress: e.ResolverAddress,
			Failure:         e.Failure,
			Finished:        now,
			ResolverNetwork: e.ResolverNetwork,
			Query:           e.Query,
			Reply:           e.Reply,
			Started:         now,
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
func (thm *THResponse) URLAddressList(domain string) (o []*measurex.URLAddress, v bool) {
	if thm != nil {
		// Important: here we need to exclude the DNS results from the TH
		// from the planning and only focus on its endpoints results otherwise
		// we may pick up an IP addr that the TH _has not_ tested.
		o, v = measurex.NewURLAddressList(
			thm.URLMeasurementID, domain, []*measurex.DNSLookupMeasurement{}, thm.Endpoint)
	}
	return
}

func (c *Client) measureAdditionalEndpoints(ctx context.Context,
	mx measurex.AbstractMeasurer, ssm *SingleStepMeasurement) {
	addrslist, _ := c.expandProbeKnowledge(mx, ssm)
	// Here we need to specify "measure again" because the addresses appear to be
	// already tested though it's the TH that has tested them, not us.
	plan, _ := ssm.ProbeInitial.NewEndpointPlanWithAddressList(
		addrslist, measurex.EndpointPlanningMeasureAgain)
	if len(plan) > 0 {
		logcat.Substep("checking for and testing additional addresses in TH results")
		for m := range mx.MeasureEndpoints(ctx, plan...) {
			ssm.ProbeAdditional = append(ssm.ProbeAdditional, m)
		}
	}
}

// expandProbeKnowledge returns a list of URL addresses that extends
// the original list known to the probe by adding IP addresses that the
// TH discovered and the probe didn't know about.
//
// Because we return more IP addresses, this means we'll exceed the
// budget for the maximum number of addresses. However, doing that is
// important when there's local DNS censorship, so it makes sense to
// do that and ensure we also test those extra addrs.
//
// The boolean returned value is true if we have at least one IP address
// to return and false otherwise. Beware that returning a non-empty
// list doesn't imply that the probe will end up testing it. Limitations
// on the maximum number of addresses per family apply.
func (c *Client) expandProbeKnowledge(mx measurex.AbstractMeasurer,
	ssm *SingleStepMeasurement) ([]*measurex.URLAddress, bool) {
	// 1. gather the lists for the probe and the th
	pal, _ := ssm.probeInitialURLAddressList()
	thal, _ := ssm.testHelperURLAddressList()
	// 2. only keep new addresses
	diff := measurex.NewURLAddressListDiff(thal, pal)
	for _, e := range diff.NewEntries {
		logcat.Celebratef("discovered new %s address for %s", e.Address, e.Domain)
	}
	return diff.NewEntries, len(diff.NewEntries) > 0
}

func (ssm *SingleStepMeasurement) probeInitialURLAddressList() (
	out []*measurex.URLAddress, good bool) {
	if ssm.ProbeInitial != nil {
		return ssm.ProbeInitial.URLAddressList()
	}
	return nil, false
}

func (ssm *SingleStepMeasurement) testHelperURLAddressList() (
	out []*measurex.URLAddress, good bool) {
	if ssm.TH != nil {
		return ssm.TH.URLAddressList(ssm.ProbeInitialDomain())
	}
	return nil, false
}

func (ssm *SingleStepMeasurement) testHelperOrDNSPingURLAddressList() ([]*measurex.URLAddress, bool) {
	out, _ := ssm.testHelperURLAddressList()
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
