package websteps

//
// TH
//
// Test helper client and server.
//

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/httpx"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

// THResponseOrError is a thResponse or an error.
type THResponseOrError struct {
	// Resp is the response
	Resp *THResponse

	// Err is the error
	Err error
}

// THResponse is the response from the TH.
type THResponse struct {
	// DNS contains DNS measurements.
	DNS []*measurex.DNSLookupMeasurement

	// Endpoint contains the endpoints.
	Endpoint []*measurex.EndpointMeasurement
}

// th runs the test helper client in a background goroutine.
func (c *Client) th(ctx context.Context, cur *measurex.URLMeasurement,
	plan []*measurex.EndpointPlan) <-chan *THResponseOrError {
	out := make(chan *THResponseOrError)
	thReq := c.newTHRequest(cur, plan)
	go c.THRequestAsync(ctx, thReq, out)
	return out
}

// THRequest is a request for the TH service.
type THRequest struct {
	// URL is the current URL.
	URL string

	// Options contains the options. Nil means using defaults.
	Options *measurex.Options

	// Plan is the endpoint measurement plan.
	Plan []THRequestEndpointPlan
}

// THRequestEndpointPlan is the plan for measuring an endpoint.
type THRequestEndpointPlan struct {
	// Network is the endpoint network.
	Network string

	// Address it the endpoint addr.
	Address string

	// URL is the endpoint URL.
	URL string

	// Cookies is the list of cookies to use.
	Cookies []string
}

// newTHRequest creates a new thRequest.
func (c *Client) newTHRequest(cur *measurex.URLMeasurement,
	plan []*measurex.EndpointPlan) *THRequest {
	return &THRequest{
		URL:     cur.URL.String(),
		Options: cur.Options,
		Plan:    c.newTHRequestEndpointPlan(plan),
	}
}

// newTHRequestEndpointPlan creates the endpoints plan for the TH.
func (c *Client) newTHRequestEndpointPlan(
	in []*measurex.EndpointPlan) (out []THRequestEndpointPlan) {
	for _, e := range in {
		out = append(out, THRequestEndpointPlan{
			Network: string(e.Network),
			Address: e.Address,
			URL:     e.URL.String(),
			Cookies: measurex.SerializeCookies(e.Cookies),
		})
	}
	return
}

// THRequestAsync performs an async TH request posting the result on the out channel.
func (c *Client) THRequestAsync(
	ctx context.Context, thReq *THRequest, out chan<- *THResponseOrError) {
	tmpl := httpx.APIClientTemplate{
		BaseURL:    c.thURL,
		HTTPClient: c.httpClient,
		Logger:     c.logger,
		UserAgent:  c.userAgent,
	}
	apic := tmpl.Build()
	var thResp THResponse
	err := apic.PostJSON(ctx, "/", thReq, &thResp)
	if err != nil {
		c.logger.Warnf("websteps: TH API call failed: %s", err.Error())
		out <- &THResponseOrError{Err: err}
		return
	}
	out <- &THResponseOrError{Resp: &thResp}
}

// THHandler handles TH requests.
type THHandler struct {
	// Logger is the logger to use.
	Logger model.Logger

	// Resolvers contains the resolvers to use.
	Resolvers []*measurex.DNSResolverInfo
}

// THHMaxAcceptableRequestBodySize is the maximum body size accepted by THHandler.
const THHMaxAcceptableRequestBodySize = 1 << 20

// ServeHTTP implements http.Handler.ServeHTTP.
func (thh *THHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(400)
		return
	}
	reader := io.LimitReader(req.Body, THHMaxAcceptableRequestBodySize)
	data, err := netxlite.ReadAllContext(req.Context(), reader)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var thReq THRequest
	if err := json.Unmarshal(data, &thReq); err != nil {
		w.WriteHeader(400)
		return
	}
	thResp, err := thh.step(req.Context(), &thReq)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	// We assume that the following call cannot fail because it's a
	// clearly serializable data structure.
	data, err = json.Marshal(thResp)
	runtimex.PanicOnError(err, "json.Marshal failed")
	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}

// step executes the TH step.
func (thh *THHandler) step(
	ctx context.Context, req *THRequest) (*THResponse, error) {
	var err error
	library := measurex.NewDefaultLibrary(thh.Logger)
	mx := measurex.NewMeasurer(thh.Logger, library)
	mx.Options, err = thh.fillOrRejectOptions(req.Options)
	if err != nil {
		return nil, err
	}
	um, err := mx.NewURLMeasurement(req.URL)
	if err != nil {
		return nil, err
	}
	dnsplan := um.NewDNSLookupPlan(thh.Resolvers)
	for m := range mx.DNSLookups(ctx, dnsplan) {
		um.DNS = append(um.DNS, m)
	}
	thh.addProbeDNS(mx, um, req.Plan)
	// Implementation note: of course it doesn't make sense here for the
	// test helper to follow bogons discovered by the client :^)
	epplan, _ := um.NewEndpointPlan(thh.Logger, measurex.EndpointPlanningExcludeBogons)
	for m := range mx.MeasureEndpoints(ctx, epplan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	return thh.serialize(um), nil
}

func (thh *THHandler) serialize(in *measurex.URLMeasurement) *THResponse {
	out := &THResponse{
		DNS:      thh.simplifyDNS(in.DNS),
		Endpoint: thh.simplifyEndpoints(in.Endpoint),
	}
	return out
}

// thhResponseTime is the time used for time variables in responses returned
// by the test helper. Because time is different in each system, there is little
// utility in returning the real time to the OONI Probe user.
var thhResponseTime = time.Date(2022, time.March, 05, 22, 44, 00, 0, time.UTC)

// simplifyDNS only keeps the fields that we want to send to clients.
func (thh *THHandler) simplifyDNS(
	in []*measurex.DNSLookupMeasurement) (out []*measurex.DNSLookupMeasurement) {
	for _, entry := range in {
		out = append(out, &measurex.DNSLookupMeasurement{
			ID:               0,
			URLMeasurementID: 0,
			Lookup: &archival.FlatDNSLookupEvent{
				ALPNs:           entry.ALPNs(),
				Addresses:       entry.Addresses(),
				Domain:          entry.Domain(),
				Failure:         entry.Failure(),
				Finished:        thhResponseTime,
				LookupType:      entry.LookupType(),
				ResolverAddress: entry.ResolverAddress(),
				ResolverNetwork: entry.ResolverNetwork(),
				Started:         thhResponseTime,
			},
			RoundTrip: []*archival.FlatDNSRoundTripEvent{},
		})
	}
	return
}

// simplifyEndpoints only keeps the fields that we want to send to clients.
func (thh *THHandler) simplifyEndpoints(
	in []*measurex.EndpointMeasurement) (out []*measurex.EndpointMeasurement) {
	for _, entry := range in {
		out = append(out, &measurex.EndpointMeasurement{
			ID:               0,
			URLMeasurementID: 0,
			URL:              entry.URL,
			Network:          entry.Network,
			Address:          entry.Address,
			OrigCookies:      entry.OrigCookies,
			Failure:          entry.Failure,
			FailedOperation:  entry.FailedOperation,
			NewCookies:       entry.NewCookies,
			Location:         entry.Location,
			NetworkEvent:     []*archival.FlatNetworkEvent{},
			TCPConnect:       nil,
			QUICTLSHandshake: nil,
			HTTPRoundTrip:    thh.simplifyHTTPRoundTrip(entry.HTTPRoundTrip),
		})
	}
	return
}

// simplifyHTTPRoundTrip only keeps the fields that we want to send to clients.
func (thh *THHandler) simplifyHTTPRoundTrip(
	in *archival.FlatHTTPRoundTripEvent) (out *archival.FlatHTTPRoundTripEvent) {
	if in != nil {
		out = &archival.FlatHTTPRoundTripEvent{
			Failure:                 in.Failure,
			Finished:                thhResponseTime,
			Method:                  in.Method,
			RequestHeaders:          in.RequestHeaders,
			ResponseBody:            nil,
			ResponseBodyIsTruncated: in.ResponseBodyIsTruncated,
			ResponseBodyLength:      in.ResponseBodyLength,
			ResponseHeaders:         in.ResponseHeaders,
			Started:                 thhResponseTime,
			StatusCode:              in.StatusCode,
			Transport:               in.Transport,
			URL:                     in.URL,
		}
	}
	return
}

// THHMaxResponseBodySnapshotSize is the maximum snapshot size
// accepted by the THHandle from client options.
const THHMaxResponseBodySnapshotSize = 1 << 22

// ErrInvalidTHHOptions indicates that some options have invalid values.
var ErrInvalidTHHOptions = errors.New("THHandle: invalid measurex.Options")

// fillOrRejectOptions fills options for the THHandler. This function just
// honours a bunch of options and otherwise forces defaults. If some values
// are incompatible with our policy, we return an error.
func (thh *THHandler) fillOrRejectOptions(clnto *measurex.Options) (*measurex.Options, error) {
	clnto = clnto.Flatten() // works even if cur is nil
	tho := &measurex.Options{
		// options for which we ignore client settings and use defaults
		ALPN:                  []string{},
		DNSLookupTimeout:      0,
		DNSParallelism:        0,
		EndpointParallelism:   0,
		HTTPGetTimeout:        0,
		HTTPHostHeader:        "",
		MaxAddressesPerFamily: 0,
		MaxCrawlerDepth:       0,
		Parent:                nil,
		QUICHandshakeTimeout:  0,
		TCPconnectTimeout:     0,
		TLSHandshakeTimeout:   0,
		SNI:                   "",
		// options for which we use clients settings if they're okay
		HTTPRequestHeaders:                           map[string][]string{},
		DoNotInitiallyForceHTTPAndHTTPS:              false,
		MaxHTTPResponseBodySnapshotSize:              0,
		MaxHTTPSResponseBodySnapshotSizeConnectivity: 0,
		MaxHTTPSResponseBodySnapshotSizeThrottling:   0,
	}
	// 1. HTTPRequestHeaders
	copiedHeaders := []string{
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Referer",
	}
	for _, key := range copiedHeaders {
		if value := clnto.HTTPRequestHeaders.Get(key); value != "" {
			tho.HTTPRequestHeaders.Set(key, value)
		}
	}
	// 2. DoNotInitiallyForceHTTPAndHTTPS
	tho.DoNotInitiallyForceHTTPAndHTTPS = clnto.DoNotInitiallyForceHTTPAndHTTPS
	// 3. MaxHTTPResponseBodySnapshotSize
	if clnto.MaxHTTPResponseBodySnapshotSize > THHMaxResponseBodySnapshotSize {
		return nil, ErrInvalidTHHOptions
	}
	tho.MaxHTTPResponseBodySnapshotSize = clnto.MaxHTTPResponseBodySnapshotSize
	// 4. MaxHTTPSResponseBodySnapshotSizeConnectivity
	if clnto.MaxHTTPSResponseBodySnapshotSizeConnectivity > THHMaxResponseBodySnapshotSize {
		return nil, ErrInvalidTHHOptions
	}
	tho.MaxHTTPSResponseBodySnapshotSizeConnectivity = clnto.MaxHTTPSResponseBodySnapshotSizeConnectivity
	// 5. MaxHTTPSResponseBodySnapshotSizeThrottling
	if clnto.MaxHTTPSResponseBodySnapshotSizeThrottling > THHMaxResponseBodySnapshotSize {
		return nil, ErrInvalidTHHOptions
	}
	tho.MaxHTTPSResponseBodySnapshotSizeThrottling = clnto.MaxHTTPSResponseBodySnapshotSizeThrottling
	return tho, nil
}

// addProbeDNS extends a DNS measurement with fake measurements
// generated from the client-supplied endpoints plan.
func (thh *THHandler) addProbeDNS(mx *measurex.Measurer,
	um *measurex.URLMeasurement, plan []THRequestEndpointPlan) {
	var addrs []string
	for _, e := range plan {
		addr, _, err := net.SplitHostPort(e.Address)
		if err != nil {
			thh.Logger.Warnf("addProbeDNS: cannot split host and port: %s", err.Error())
			continue
		}
		addrs = append(addrs, addr)
	}
	um.AddFromExternalDNSLookup(mx, "external", "probe", nil, addrs...)
}

// NewTHHandler creates a new TH handler with default settings.
func NewTHHandler(logger model.Logger) *THHandler {
	return &THHandler{
		Logger:    logger,
		Resolvers: thhResolvers,
	}
}

// thhResolvers contains the static list of resolvers used by the THHandler.
var thhResolvers = []*measurex.DNSResolverInfo{{
	Network: "doh",
	Address: "https://dns.google/dns-query",
}}
