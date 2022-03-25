package websteps

//
// TH
//
// Test helper client and server.
//

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
	"github.com/gorilla/websocket"
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
	// StillRunning is a boolean flag that tells the client that
	// the test helper is still alive and running.
	StillRunning bool `json:",omitempty"`

	// URLMeasurementID is the URL measurement ID. We do not
	// serialize this field to JSON since that would be redundant.
	URLMeasurementID int64 `json:"-"`

	// DNS contains DNS measurements.
	DNS []*measurex.DNSLookupMeasurement

	// Endpoint contains the endpoints.
	Endpoint []*measurex.EndpointMeasurement
}

// ToArchival converts THResponse to its archival data format.
func (r *THResponse) ToArchival(begin time.Time) ArchivalTHResponse {
	// Here it's fine to pass empty flags because we're serializing
	// the TH response which does not contain the body
	const bodyFlags = 0
	return ArchivalTHResponse{
		DNS: measurex.NewArchivalDNSLookupMeasurementList(begin, r.DNS),
		Endpoint: measurex.NewArchivalEndpointMeasurementList(
			begin, r.Endpoint, bodyFlags),
	}
}

// th runs the test helper client in a background goroutine.
func (c *Client) th(ctx context.Context, cur *measurex.URLMeasurement,
	plan []*measurex.EndpointPlan) <-chan *THResponseOrError {
	logcat.Substepf("while continuing to measure, I'll query the test helper (TH) in the background")
	out := make(chan *THResponseOrError, 1)
	thReq := c.newTHRequest(cur, plan)
	go c.THRequestAsync(ctx, thReq, out)
	return out
}

// THRequest sends a THRequest to the TH and waits for a response.
func (c *Client) THRequest(ctx context.Context, req *THRequest) (*THResponse, error) {
	out := make(chan *THResponseOrError, 1)
	go c.THRequestAsync(ctx, req, out)
	resp := <-out // context cancellaton handled in THRequestAsync
	if resp.Err != nil {
		return nil, resp.Err
	}
	return resp.Resp, nil
}

// THRequest is a request for the TH service.
type THRequest struct {
	// URL is the current URL.
	URL string

	// Options contains the options. Nil means using defaults.
	Options *measurex.Options `json:",omitempty"`

	// Cookies is the list of cookies to use.
	Cookies []string

	// Plan is the endpoint measurement plan.
	Plan []THRequestEndpointPlan `json:",omitempty"`
}

// THRequestEndpointPlan is the plan for measuring an endpoint.
type THRequestEndpointPlan struct {
	// Network is the endpoint network.
	Network string

	// Address it the endpoint addr.
	Address string

	// URL is the endpoint URL.
	URL string
}

// newTHRequest creates a new thRequest.
func (c *Client) newTHRequest(cur *measurex.URLMeasurement,
	plan []*measurex.EndpointPlan) *THRequest {
	return &THRequest{
		URL:     cur.URL.String(),
		Options: cur.Options,
		Cookies: measurex.SerializeCookies(cur.Cookies),
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
		})
	}
	return
}

// THRequestAsync performs an async TH request posting the result on the out channel. The
// output channel MUST be buffered with one place in the buffer.
func (c *Client) THRequestAsync(
	ctx context.Context, thReq *THRequest, out chan<- *THResponseOrError) {
	// TODO(bassosimone): research keeping a persistent conn with
	// the server to improve the TH performance.
	conn, err := c.websocketDial(ctx)
	if err != nil {
		out <- &THResponseOrError{Err: err}
		return // error already printed
	}
	defer conn.Close()
	if err := c.websocketSend(conn, thReq); err != nil {
		out <- &THResponseOrError{Err: err}
		return // error already printed
	}
	bout := make(chan *THResponseOrError, 1) // buffered channel!
	go c.websocketRecvAsync(conn, bout)
	select {
	case <-ctx.Done():
		out <- &THResponseOrError{Err: ctx.Err()}
	case m := <-bout:
		out <- m
	}
}

// websocketDial establishes a websocket conn with the test helper. The returned
// conn has hard deadlines, so we can ensure liveness.
func (c *Client) websocketDial(ctx context.Context) (*websocket.Conn, error) {
	dialer := &websocket.Dialer{
		NetDial:           nil,
		NetDialContext:    c.dialContextFunc(),
		NetDialTLSContext: c.dialTLSContextFunc(),
		Proxy:             nil,
		TLSClientConfig:   nil, // not needed because we override NetDialTLSContext
		HandshakeTimeout:  10 * time.Second,
		ReadBufferSize:    0,
		WriteBufferSize:   0,
		WriteBufferPool:   nil,
		Subprotocols:      []string{},
		EnableCompression: false,
		Jar:               nil,
	}
	conn, _, err := dialer.DialContext(ctx, c.thURL, http.Header{})
	if err != nil {
		logcat.Shrugf("[thclient] cannot dial: %s", err.Error())
		return nil, err
	}
	const timeout = 90 * time.Second
	deadline := time.Now().Add(timeout)
	conn.SetWriteDeadline(deadline)
	conn.SetReadDeadline(deadline)
	return conn, nil
}

// dialContextFunc returns the DialContext func we should be using.
func (c *Client) dialContextFunc() func(ctx context.Context,
	network, address string) (net.Conn, error) {
	if c.dialerCleartext != nil {
		return c.dialerCleartext.DialContext
	}
	d := &net.Dialer{}
	return d.DialContext
}

// dialTLSContextFunc returns the dialTLSContext func we should be using.
func (c *Client) dialTLSContextFunc() func(ctx context.Context,
	network, address string) (net.Conn, error) {
	if c.dialerTLS != nil {
		return c.dialerTLS.DialTLSContext
	}
	d := &tls.Dialer{
		Config: &tls.Config{
			RootCAs: netxlite.NewDefaultCertPool(),
		},
	}
	return d.DialContext
}

// websocketSend sends the request to the server.
func (c *Client) websocketSend(conn *websocket.Conn, thReq *THRequest) error {
	// The following call to json.Marshal cannot actually fail
	data, err := json.Marshal(thReq)
	runtimex.PanicOnError(err, "json.Marshal failed")
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		logcat.Shrugf("[thclient] cannot write: %s", err.Error())
		return err
	}
	return nil
}

// websocketRecvAsync receives the response from the server asynchronously
// from a background goroutine created by the caller.
func (c *Client) websocketRecvAsync(conn *websocket.Conn, out chan<- *THResponseOrError) {
	for {
		mtype, reader, err := conn.NextReader()
		if err != nil {
			logcat.Shrugf("[thclient] cannot read message header: %s", err.Error())
			out <- &THResponseOrError{Err: err}
			return
		}
		if mtype != websocket.TextMessage {
			logcat.Bugf("[thclient] unexpected message type: %d", mtype)
			out <- &THResponseOrError{Err: err}
			return
		}
		reader = io.LimitReader(reader, THHMaxAcceptableWebSocketMessage)
		data, err := netxlite.ReadAllContext(context.Background(), reader)
		if err != nil {
			logcat.Shrugf("[thclient] cannot read message body: %s", err.Error())
			out <- &THResponseOrError{Err: err}
			return
		}
		var thResp THResponse
		if err := json.Unmarshal(data, &thResp); err != nil {
			logcat.Bugf("[thclient] cannot unmarshal message: %s", err.Error())
			out <- &THResponseOrError{Err: err}
			return
		}
		if thResp.StillRunning {
			continue // message sent to keep the connection alive
		}
		out <- &THResponseOrError{
			Err:  nil,
			Resp: &thResp,
		}
		// Because we've received our response, stop reading
		return
	}
}

// THHandlerSaver allows to save THHandler results.
type THHandlerSaver interface {
	// Save saves this measurement somewhere.
	Save(um *measurex.URLMeasurement)
}

// MeasurerFactory is a factory for creating a measurer.
type MeasurerFactory func(options *measurex.Options) (measurex.AbstractMeasurer, error)

// THHandlerOptions contains options for the THHandler.
type THHandlerOptions struct {
	// MeasurerFactory is the OPTIONAL factory used
	// to construct a measurer. By changing this
	// factory, you can force the THHandler to use
	// a different measurer (e.g., a caching measurer).
	MeasurerFactory MeasurerFactory

	// Resolvers contains the resolvers to use.
	Resolvers []*measurex.DNSResolverInfo

	// Saver saves measurements.
	Saver THHandlerSaver
}

// THHandler handles TH requests.
type THHandler struct {
	// Options contains the TH handler options.
	Options *THHandlerOptions

	// IDGenerator generates the next ID.
	IDGenerator *measurex.IDGenerator
}

// THHMaxAcceptableWebSocketMessage is the maximum websocket message size.
const THHMaxAcceptableWebSocketMessage = 1 << 20

// ServeHTTP implements http.Handler.ServeHTTP.
func (thh *THHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	thr := thh.newTHRequestHandler()
	thr.do(w, req)
}

func (thr *THRequestHandler) do(w http.ResponseWriter, req *http.Request) {
	conn, err := thr.upgrade(w, req)
	if err != nil {
		return // error already logged
	}
	defer conn.Close()
	thReq, err := thr.readMsg(conn)
	if err != nil {
		return // error already logged
	}
	go thr.discardIncomingMessages(conn)
	out := thr.waitForCompletion(conn, thr.stepAsync(thReq))
	if out.Err != nil {
		return // error already printed
	}
	if err := thr.writeToClient(conn, out.Resp); err != nil {
		return // error already printed
	}
	_ = thr.gracefulClose(conn)
}

// gracefulClose closes the websocket connection gracefully.
func (thr *THRequestHandler) gracefulClose(conn *websocket.Conn) error {
	const closeTimeout = time.Second
	deadline := time.Now().Add(closeTimeout)
	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	return conn.WriteControl(websocket.CloseMessage, msg, deadline)
}

// upgrade will upgrade to WebSocket or fail. The returned connection has
// a strict maximum deadline that guarantees liveness.
func (thr *THRequestHandler) upgrade(
	w http.ResponseWriter, req *http.Request) (*websocket.Conn, error) {
	upgrader := &websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   0,
		WriteBufferSize:  0,
		WriteBufferPool:  nil,
		Subprotocols:     []string{},
		Error:            nil,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow cross origin resource sharing
		},
		EnableCompression: false,
	}
	conn, err := upgrader.Upgrade(w, req, http.Header{})
	if err != nil {
		logcat.Shrugf("[thh] cannot upgrade to websocket: %s", err.Error())
		return nil, err
	}
	const timeout = 90 * time.Second
	deadline := time.Now().Add(timeout)
	conn.SetWriteDeadline(deadline)
	conn.SetReadDeadline(deadline)
	return conn, nil
}

// readMsg will read the client request or fail.
func (thr *THRequestHandler) readMsg(conn *websocket.Conn) (*THRequest, error) {
	mtype, reader, err := conn.NextReader()
	if err != nil {
		logcat.Shrugf("[thh] cannot read message header: %s", err.Error())
		return nil, err
	}
	if mtype != websocket.TextMessage {
		logcat.Shrugf("[thh] received non-text message")
		return nil, err
	}
	reader = io.LimitReader(reader, THHMaxAcceptableWebSocketMessage)
	data, err := netxlite.ReadAllContext(context.Background(), reader)
	if err != nil {
		logcat.Shrugf("[thh] cannot read message body: %s", err.Error())
		return nil, err
	}
	var thReq THRequest
	if err := json.Unmarshal(data, &thReq); err != nil {
		logcat.Shrugf("[thh] cannot unmarshal message: %s", err.Error())
		return nil, err
	}
	return &thReq, nil
}

// stepAsync performs a websteps step asynchronously.
func (thr *THRequestHandler) stepAsync(thReq *THRequest) <-chan *THResponseOrError {
	outch := make(chan *THResponseOrError)
	go func() {
		r := &THResponseOrError{}
		r.Resp, r.Err = thr.step(context.Background(), thReq)
		outch <- r
	}()
	return outch
}

// discardIncomingMessages just discards incoming messages. We need to
// be reading because of how gorilla/websocket works.
func (thr *THRequestHandler) discardIncomingMessages(conn *websocket.Conn) {
	for {
		if _, _, err := conn.NextReader(); err != nil {
			return
		}
	}
}

// waitForCompletion waits for the async step to complete and, while there,
// periodically sends status updates.
func (thr *THRequestHandler) waitForCompletion(conn *websocket.Conn,
	outch <-chan *THResponseOrError) *THResponseOrError {
	const interval = 500 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case out := <-outch:
			return out
		case <-ticker.C:
			thResp := &THResponse{
				StillRunning: true,
				DNS:          []*measurex.DNSLookupMeasurement{},
				Endpoint:     []*measurex.EndpointMeasurement{},
			}
			if err := thr.writeToClient(conn, thResp); err != nil {
				return &THResponseOrError{Err: err} // error already printed
			}
		}
	}
}

// writeToClient writes a message to the client.
func (thr *THRequestHandler) writeToClient(conn *websocket.Conn, thResp *THResponse) error {
	// We assume that the following call cannot fail because it's a
	// clearly serializable data structure.
	data, err := json.Marshal(thResp)
	runtimex.PanicOnError(err, "json.Marshal failed")
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		logcat.Shrugf("[thh] cannot write message: %s", err.Error())
		return err
	}
	return nil
}

// THRequestHandler handles a single request from a client.
type THRequestHandler struct {
	// Options contains the options.
	Options *THHandlerOptions

	// ID is the unique ID of this request.
	ID int64
}

// resolvers returns the resolvers to use.
func (thr *THRequestHandler) resolvers() []*measurex.DNSResolverInfo {
	if thr.Options != nil && thr.Options.Resolvers != nil {
		return thr.Options.Resolvers
	}
	return thhResolvers
}

// measurerFactory constructs a new measurer either using the
// thr.Option's MeasurerFactory or a default factory.
func (thr *THRequestHandler) measurerFactory(
	options *measurex.Options) (measurex.AbstractMeasurer, error) {
	if thr.Options != nil && thr.Options.MeasurerFactory != nil {
		return thr.Options.MeasurerFactory(options)
	}
	lib := measurex.NewDefaultLibrary()
	mx := measurex.NewMeasurerWithOptions(lib, options)
	return mx, nil
}

// step executes the TH step.
func (thr *THRequestHandler) step(
	ctx context.Context, req *THRequest) (*THResponse, error) {
	options, err := thr.fillOrRejectOptions(req.Options)
	if err != nil {
		return nil, err
	}
	mx, err := thr.measurerFactory(options)
	if err != nil {
		return nil, err
	}
	um, err := mx.NewURLMeasurement(req.URL)
	if err != nil {
		return nil, err
	}
	const flags = 0 // no extra lookups
	dnsplan := um.NewDNSLookupPlans(flags, thr.resolvers()...)
	for m := range mx.DNSLookups(ctx, dnsplan...) {
		thr.maybeGatherCNAME(m)
		um.DNS = append(um.DNS, m)
	}
	probeAddrs := thr.addProbeDNS(mx, um, req.Plan)
	revch := thr.reverseDNSLookupAsync(ctx, mx, um, probeAddrs)
	// Implementation note: of course it doesn't make sense here for the
	// test helper to follow bogons discovered by the client :^)
	epplan, _ := um.NewEndpointPlan(measurex.EndpointPlanningExcludeBogons)
	epplan = thr.patchEndpointPlan(epplan, req, probeAddrs)
	for m := range mx.MeasureEndpoints(ctx, epplan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	// second round where we follow Alt-Svc leads
	epplan, _ = um.NewEndpointPlan(
		measurex.EndpointPlanningExcludeBogons | measurex.EndpointPlanningOnlyHTTP3)
	for m := range mx.MeasureEndpoints(ctx, epplan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	um.DNS = append(um.DNS, <-revch...) // merge async results of the reverse lookup
	thr.saver().Save(um)                // allows saving the measurement for analysis
	return thr.serialize(um), nil
}

// reverseDNSLookupAsync performs a reverse DNS lookup for all the IP addresses we know.
func (thr *THRequestHandler) reverseDNSLookupAsync(ctx context.Context, mx measurex.AbstractMeasurer,
	um *measurex.URLMeasurement, probeAddrs []string) <-chan []*measurex.DNSLookupMeasurement {
	out := make(chan []*measurex.DNSLookupMeasurement)
	go func() {
		// 0. close channel when done, we'll return a nil list in the worst case
		defer close(out)
		// 1. build a list of unique IP addresses to reverse lookup
		uniqm := map[string]int{}
		for _, dns := range um.DNS {
			for _, addr := range dns.Addresses() {
				uniqm[addr]++
			}
		}
		for _, addr := range probeAddrs {
			uniqm[addr]++
		}
		uniq := []string{}
		for addr := range uniqm {
			uniq = append(uniq, addr)
		}
		// 2. generate a reverse lookup plan
		plan := um.NewDNSReverseLookupPlans(uniq, thr.resolvers()...)
		// 3. collect results
		v := []*measurex.DNSLookupMeasurement{}
		for m := range mx.DNSLookups(ctx, plan...) {
			v = append(v, m)
		}
		// 4. return results to the caller.
		out <- v
	}()
	return out
}

// patchEndpointPlan returns a modified endpoint plan where:
//
// 1. we include cookies from the probe (if any);
//
// 2. we ensure we're testing a few extra IP addresses than the
// addresses discovered by the probe (so that, in turn, the probe
// will always have some extra addresses to measure).
//
// The returned plan is a new list with cloned and modified entries.
func (thr *THRequestHandler) patchEndpointPlan(input []*measurex.EndpointPlan,
	r *THRequest, probeAddrs []string) (out []*measurex.EndpointPlan) {

	// 1. prepare the list of cookies to include
	cookies := measurex.ParseCookies(r.Cookies...)

	// 2. track non-bogon IP addresses discovered by the probe
	inprobe := map[string]bool{}
	for _, addr := range probeAddrs {
		if netxlite.IsBogon(addr) {
			continue // no point in following bogons here
		}
		inprobe[addr] = true
	}

	// 3. exclude entries from the plan. We ensure that all non-bogon IP
	// addresses discovered by the probe are included, plus at most a small
	// number of other IP addresses that the probe didn't know about.
	extra4, extra6 := map[string]bool{}, map[string]bool{}
	out = []*measurex.EndpointPlan{}
	for _, e := range input {
		ipaddr := e.IPAddress()
		if ipaddr == "" {
			continue // something wrong with this entry
		}
		if !inprobe[ipaddr] {
			const threshold = 1 // we don't want to test too many addrs
			isipv6, _ := netxlite.IsIPv6(ipaddr)
			switch isipv6 {
			case true:
				if !extra6[ipaddr] && len(extra6) >= threshold {
					logcat.Infof("patchEndpointPlan: too many extra AAAA addrs already; skipping %s", ipaddr)
					continue // already too many extra IPv6 addresses
				}
				extra6[ipaddr] = true
			case false:
				if !extra4[ipaddr] && len(extra4) >= threshold {
					logcat.Infof("patchEndpointPlan: too many extra A addrs already; skipping %s", ipaddr)
					continue // already too many IPv4 addresses
				}
				extra4[ipaddr] = true
			}
			// fallthrough
		} else {
			logcat.Infof("patchEndpointPlan: include %s provided by the probe", ipaddr)
		}
		out = append(out, &measurex.EndpointPlan{
			URLMeasurementID: e.URLMeasurementID,
			Domain:           e.Domain,
			Network:          e.Network,
			Address:          e.Address,
			URL:              e.URL.Clone(),
			Options:          e.Options.Flatten(),
			Cookies:          cookies,
		})
	}

	return
}

// maybeGatherCNAME attempts to gather a CNAME for the given DNSLookupMeasurement.
func (thr *THRequestHandler) maybeGatherCNAME(m *measurex.DNSLookupMeasurement) {
	if m != nil && m.Lookup != nil {
		m.Lookup.CNAME = archival.MaybeGatherCNAME(m.RoundTrip)
	}
}

// saver returns the saver or the default.
func (thr *THRequestHandler) saver() THHandlerSaver {
	if thr.Options != nil && thr.Options.Saver != nil {
		return thr.Options.Saver
	}
	return &thHandlerSaverNull{}
}

// thHandlerSaverNull is the default THHandlerSaver.
type thHandlerSaverNull struct{}

func (*thHandlerSaverNull) Save(um *measurex.URLMeasurement) {
	// nothing
}

func (thr *THRequestHandler) serialize(in *measurex.URLMeasurement) *THResponse {
	out := &THResponse{
		DNS:      thr.simplifyDNS(in.DNS),
		Endpoint: thr.simplifyEndpoints(in.Endpoint),
	}
	return out
}

// thhResponseTime is the time used for time variables in responses returned
// by the test helper. Because time is different in each system, there is little
// utility in returning the real time to the OONI Probe user.
var thhResponseTime = time.Date(2022, time.March, 05, 22, 44, 00, 0, time.UTC)

// simplifyDNS only keeps the fields that we want to send to clients.
func (thr *THRequestHandler) simplifyDNS(
	in []*measurex.DNSLookupMeasurement) (out []*measurex.DNSLookupMeasurement) {
	for _, entry := range in {
		// We expect the TH to always use DoH. If we see any different network here it
		// should be a bug. Unless the network is "external". In such case we're just
		// looking at the probe measurements imported by the TH.
		if entry.ResolverNetwork() != archival.NetworkTypeDoH {
			if v := entry.ResolverNetwork(); v != "external" {
				logcat.Bugf("unexpected resolver network: %s", v)
			}
			continue
		}
		out = append(out, &measurex.DNSLookupMeasurement{
			ID:               0,
			URLMeasurementID: 0,
			ReverseAddress:   entry.ReverseAddress,
			Lookup: &archival.FlatDNSLookupEvent{
				ALPNs:           entry.ALPNs(),
				Addresses:       entry.Addresses(),
				CNAME:           entry.CNAME(),
				Domain:          entry.Domain(),
				Failure:         entry.Failure(),
				Finished:        thhResponseTime,
				LookupType:      entry.LookupType(),
				NS:              entry.NS(),
				PTRs:            entry.PTRs(),
				ResolverAddress: entry.ResolverAddress(),
				ResolverNetwork: entry.ResolverNetwork(),
				Started:         thhResponseTime,
			},
			RoundTrip: thr.simplifyDNSRoundTrip(entry.RoundTrip),
		})
	}
	return
}

// simplifyDNSRoundTrip only keeps the records we want to send to clients.
func (thr *THRequestHandler) simplifyDNSRoundTrip(
	in []*archival.FlatDNSRoundTripEvent) (out []*archival.FlatDNSRoundTripEvent) {
	for _, e := range in {
		out = append(out, &archival.FlatDNSRoundTripEvent{
			ResolverAddress: e.ResolverAddress,
			Failure:         e.Failure,
			Finished:        thhResponseTime,
			ResolverNetwork: e.ResolverNetwork,
			Query:           e.Query,
			Reply:           e.Reply,
			Started:         thhResponseTime,
		})
	}
	return
}

// simplifyEndpoints only keeps the fields that we want to send to clients.
func (thr *THRequestHandler) simplifyEndpoints(
	in []*measurex.EndpointMeasurement) (out []*measurex.EndpointMeasurement) {
	for _, entry := range in {
		out = append(out, &measurex.EndpointMeasurement{
			ID:               0,
			URLMeasurementID: 0,
			URL:              entry.URL,
			Network:          entry.Network,
			Address:          entry.Address,
			Options:          entry.Options,
			OrigCookies:      entry.OrigCookies,
			Failure:          entry.Failure,
			FailedOperation:  entry.FailedOperation,
			NewCookies:       entry.NewCookies,
			Location:         entry.Location,
			HTTPTitle:        entry.HTTPTitle,
			NetworkEvent:     []*archival.FlatNetworkEvent{},
			TCPConnect:       nil,
			QUICTLSHandshake: nil,
			HTTPRoundTrip:    thr.simplifyHTTPRoundTrip(entry.HTTPRoundTrip),
		})
	}
	return
}

// simplifyHTTPRoundTrip only keeps the fields that we want to send to clients.
func (thr *THRequestHandler) simplifyHTTPRoundTrip(
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
			ResponseBodyTLSH:        in.ResponseBodyTLSH,
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
func (thr *THRequestHandler) fillOrRejectOptions(
	clnto *measurex.Options) (*measurex.Options, error) {
	clnto = clnto.Flatten() // works even if cur is nil
	tho := &measurex.Options{
		// options for which we ignore client settings and use defaults
		ALPN:                 []string{},
		DNSLookupTimeout:     0,
		DNSParallelism:       0,
		EndpointParallelism:  0,
		HTTPGetTimeout:       0,
		HTTPHostHeader:       "",
		MaxCrawlerDepth:      0,
		Parent:               nil,
		QUICHandshakeTimeout: 0,
		TCPconnectTimeout:    0,
		TLSHandshakeTimeout:  0,
		SNI:                  "",
		// options for which the defaults are not good enough
		MaxAddressesPerFamily: 32,
		// options for which we use clients settings if they're okay
		HTTPExtractTitle:                             false,
		HTTPRequestHeaders:                           map[string][]string{},
		DoNotInitiallyForceHTTPAndHTTPS:              false,
		MaxHTTPResponseBodySnapshotSize:              0,
		MaxHTTPSResponseBodySnapshotSizeConnectivity: 0,
		MaxHTTPSResponseBodySnapshotSizeThrottling:   0,
	}
	// 0. HTTPExtractTitle
	tho.HTTPExtractTitle = clnto.HTTPExtractTitle
	// 1. HTTPRequestHeaders
	copiedHeaders := []string{
		"Accept",
		"Accept-Language",
		"Referer",
		"User-Agent",
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
// generated from the client-supplied endpoints plan. This function
// returns the IP addresses discovered by the probe.
func (thr *THRequestHandler) addProbeDNS(mx measurex.AbstractMeasurer,
	um *measurex.URLMeasurement, plan []THRequestEndpointPlan) []string {
	var addrs []string
	for _, e := range plan {
		addr, _, err := net.SplitHostPort(e.Address)
		if err != nil {
			logcat.Shrugf("[thh] SplitHostPort: %s", err.Error())
			continue
		}
		addrs = append(addrs, addr)
	}
	um.AddFromExternalDNSLookup(mx, "external", "probe", nil, addrs...)
	return addrs
}

// NewTHHandler creates a new TH handler with default settings.
func NewTHHandler(options *THHandlerOptions) *THHandler {
	return &THHandler{
		Options:     options,
		IDGenerator: measurex.NewIDGenerator(),
	}
}

// newTHRequestHandler handles a single request.
func (thh *THHandler) newTHRequestHandler() *THRequestHandler {
	return &THRequestHandler{
		Options: thh.Options,
		ID:      thh.IDGenerator.NextID(),
	}
}

// thhResolvers contains the static list of resolvers used by the THHandler.
var thhResolvers = []*measurex.DNSResolverInfo{{
	Network: "doh",
	Address: "https://dns.cloudflare.com/dns-query",
}}
