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
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
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
	StillRunning bool

	// DNS contains DNS measurements.
	DNS []*measurex.DNSLookupMeasurement

	// Endpoint contains the endpoints.
	Endpoint []*measurex.EndpointMeasurement
}

// th runs the test helper client in a background goroutine.
func (c *Client) th(ctx context.Context, cur *measurex.URLMeasurement) <-chan *THResponseOrError {
	plan, _ := cur.NewEndpointPlan(c.logger, measurex.EndpointPlanningIncludeAll)
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
		c.logger.Warnf("websteps: cannot websocket-dial with server: %s", err.Error())
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
		c.logger.Warnf("websteps: cannot write using websocket: %s", err.Error())
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
			c.logger.Warnf("websteps: cannot read from server: %s", err.Error())
			out <- &THResponseOrError{Err: err}
			return
		}
		if mtype != websocket.TextMessage {
			c.logger.Warnf("websteps: unexpected message type: %d", mtype)
			out <- &THResponseOrError{Err: err}
			return
		}
		reader = io.LimitReader(reader, THHMaxAcceptableWebSocketMessage)
		data, err := netxlite.ReadAllContext(context.Background(), reader)
		if err != nil {
			c.logger.Warnf("websteps: cannot read from server: %s", err.Error())
			out <- &THResponseOrError{Err: err}
			return
		}
		var thResp THResponse
		if err := json.Unmarshal(data, &thResp); err != nil {
			c.logger.Warnf("websteps: cannot unmarshal from server: %s", err.Error())
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

// THHandlerOptions contains options for the THHandler.
type THHandlerOptions struct {
	// Logger is the logger to use.
	Logger model.Logger

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
		thr.logger().Warnf("cannot upgrade to websocket: %s", err.Error())
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
		thr.logger().Warnf("cannot upgrade to websocket: %s", err.Error())
		return nil, err
	}
	if mtype != websocket.TextMessage {
		thr.logger().Warn("received non-text message")
		return nil, err
	}
	reader = io.LimitReader(reader, THHMaxAcceptableWebSocketMessage)
	data, err := netxlite.ReadAllContext(context.Background(), reader)
	if err != nil {
		thr.logger().Warnf("cannot read websocket message: %s", err.Error())
		return nil, err
	}
	var thReq THRequest
	if err := json.Unmarshal(data, &thReq); err != nil {
		thr.logger().Warnf("cannot unmarshal websocket message: %s", err.Error())
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
		thr.logger().Warnf("cannot write messsge to client: %s", err.Error())
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

// thRequestLogger is the logger for a given request.
type thRequestLogger struct {
	Logger model.Logger
	ID     int64
}

var _ model.Logger = &thRequestLogger{}

func (thrl *thRequestLogger) Debug(message string) {
	message = fmt.Sprintf("<%d> %s", thrl.ID, message)
	thrl.Logger.Debug(message)
}

func (thrl *thRequestLogger) Debugf(format string, v ...interface{}) {
	thrl.Debug(fmt.Sprintf(format, v...))
}

func (thrl *thRequestLogger) Info(message string) {
	message = fmt.Sprintf("<%d> %s", thrl.ID, message)
	thrl.Logger.Info(message)
}

func (thrl *thRequestLogger) Infof(format string, v ...interface{}) {
	thrl.Info(fmt.Sprintf(format, v...))
}

func (thrl *thRequestLogger) Warn(message string) {
	message = fmt.Sprintf("<%d> %s", thrl.ID, message)
	thrl.Logger.Warn(message)
}

func (thrl *thRequestLogger) Warnf(format string, v ...interface{}) {
	thrl.Warn(fmt.Sprintf(format, v...))
}

// logger returns the model.Logger to use.
func (thr *THRequestHandler) logger() model.Logger {
	if thr.Options != nil && thr.Options.Logger != nil {
		return &thRequestLogger{
			Logger: thr.Options.Logger,
			ID:     thr.ID,
		}
	}
	return model.DiscardLogger
}

// resolvers returns the resolvers to use.
func (thr *THRequestHandler) resolvers() []*measurex.DNSResolverInfo {
	if thr.Options != nil && thr.Options.Resolvers != nil {
		return thr.Options.Resolvers
	}
	return thhResolvers
}

// step executes the TH step.
func (thr *THRequestHandler) step(
	ctx context.Context, req *THRequest) (*THResponse, error) {
	var err error
	library := measurex.NewDefaultLibrary(thr.logger())
	mx := measurex.NewMeasurer(thr.logger(), library)
	mx.Options, err = thr.fillOrRejectOptions(req.Options)
	if err != nil {
		return nil, err
	}
	um, err := mx.NewURLMeasurement(req.URL)
	if err != nil {
		return nil, err
	}
	dnsplan := um.NewDNSLookupPlan(thr.resolvers())
	for m := range mx.DNSLookups(ctx, dnsplan) {
		um.DNS = append(um.DNS, m)
	}
	thr.addProbeDNS(mx, um, req.Plan)
	// Implementation note: of course it doesn't make sense here for the
	// test helper to follow bogons discovered by the client :^)
	epplan, _ := um.NewEndpointPlan(thr.logger(), measurex.EndpointPlanningExcludeBogons)
	for m := range mx.MeasureEndpoints(ctx, epplan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	// second round where we follow Alt-Svc leads
	epplan, _ = um.NewEndpointPlan(thr.logger(),
		measurex.EndpointPlanningExcludeBogons|measurex.EndpointPlanningOnlyHTTP3)
	for m := range mx.MeasureEndpoints(ctx, epplan...) {
		um.Endpoint = append(um.Endpoint, m)
	}
	thr.saver().Save(um) // allows saving the measurement for analysis
	return thr.serialize(um), nil
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
func (thr *THRequestHandler) simplifyEndpoints(
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
// generated from the client-supplied endpoints plan.
func (thr *THRequestHandler) addProbeDNS(mx *measurex.Measurer,
	um *measurex.URLMeasurement, plan []THRequestEndpointPlan) {
	var addrs []string
	for _, e := range plan {
		addr, _, err := net.SplitHostPort(e.Address)
		if err != nil {
			thr.logger().Warnf("addProbeDNS: cannot split host and port: %s", err.Error())
			continue
		}
		addrs = append(addrs, addr)
	}
	um.AddFromExternalDNSLookup(mx, "external", "probe", nil, addrs...)
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
		ID:      thh.IDGenerator.Next(),
	}
}

// thhResolvers contains the static list of resolvers used by the THHandler.
var thhResolvers = []*measurex.DNSResolverInfo{{
	Network: "doh",
	Address: "https://dns.google/dns-query",
}}
