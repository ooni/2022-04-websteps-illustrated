package measurex

//
// Endpoint
//
// This file contains the definition of Endpoint.
//
// Note that this file has been changed significantly with respect
// to the namesake ooni/probe-cli's file.
//

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/lucas-clemente/quic-go"
)

var (
	// ErrUnknownURLScheme means that the given
	// endpoint's URL scheme is neither HTTP nor HTTPS.
	ErrUnknownURLScheme = errors.New("unknown URL.Scheme")

	// ErrUnknownEndpointNetwork means that the given endpoint's
	// network is of a type that we don't know how to handle.
	ErrUnknownEndpointNetwork = errors.New("unknown Endpoint.Network")
)

// EndpointPlan is the plan to measure an endpoint.
type EndpointPlan struct {
	// URLMeasurementID is the ID of the URLMeasurement that created us.
	URLMeasurementID int64

	// Domain is the endpoint domain (e.g., "dns.google").
	Domain string

	// Network is the network (e.g., "tcp" or "quic").
	Network archival.NetworkType

	// Address is the endpoint address (e.g., "8.8.8.8:443").
	Address string

	// URL is the endpoint URL.
	URL *url.URL

	// Options contains the options. A nil value implies that we're
	// going to use the default value of each option.
	Options *Options

	// Cookies contains the cookie to use when measuring.
	Cookies []*http.Cookie
}

func (e *EndpointPlan) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: e.Options.sniForEndpointPlan(e),
		NextProtos: e.Options.alpnForEndpointPlan(e),
		RootCAs:    netxlite.NewDefaultCertPool(),
	}
}

func (e *EndpointPlan) newCookieJar() http.CookieJar {
	jar := NewCookieJar()
	jar.SetCookies(e.URL, e.Cookies)
	return jar
}

// FlatFailedOperation is a flat representation of a failed operation.
type FlatFailedOperation = archival.FlatFailure

// EndpointMeasurement is an endpoint measurement.
type EndpointMeasurement struct {
	// ID is the unique ID of this measurement.
	ID int64

	// URLMeasurementID is the ID of the URLMeasurement that created us.
	URLMeasurementID int64

	// URL is the URL this measurement refers to.
	URL *url.URL

	// Network is the network of this endpoint.
	Network archival.NetworkType

	// Address is the address of this endpoint.
	Address string

	// OrigCookies contains the cookies we originally used.
	OrigCookies []*http.Cookie

	// Failure is the error that occurred.
	Failure archival.FlatFailure

	// FailedOperation is the operation that failed.
	FailedOperation FlatFailedOperation

	// NewCookies contains cookies the next redirection (if any) should use.
	NewCookies []*http.Cookie

	// Location is the URL we're redirected to (if any).
	Location *url.URL

	// NetworkEvent contains network events (if any).
	NetworkEvent []*archival.FlatNetworkEvent

	// TCPConnect contains the TCP connect event (if any).
	TCPConnect *archival.FlatNetworkEvent

	// QUICTLSHandshake contains the QUIC/TLS handshake event (if any).
	QUICTLSHandshake *archival.FlatQUICTLSHandshakeEvent

	// HTTPRoundTrip contains the HTTP round trip event (if any).
	HTTPRoundTrip *archival.FlatHTTPRoundTripEvent
}

// EndpointAddress returns a string like "{address}/{network}".
func (em *EndpointMeasurement) EndpointAddress() string {
	return fmt.Sprintf("%s/%s", em.Address, em.Network)
}

// ErrInvalidIPAddress means that we cannot parse an IP address.
var ErrInvalidIPAddress = errors.New("invalid IP address")

// IPAddress returns the IP address used in this EndpointMeasurement.
func (em *EndpointMeasurement) IPAddress() (string, error) {
	addr, _, err := net.SplitHostPort(em.Address)
	if err != nil {
		return "", err
	}
	if net.ParseIP(addr) == nil {
		return "", ErrInvalidIPAddress
	}
	return addr, nil
}

// ResponseHeaders returns the response headers. If there's no response
// we just return a set of empty headers.
func (em *EndpointMeasurement) ResponseHeaders() http.Header {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.ResponseHeaders
	}
	return http.Header{}
}

// RequestHeaders returns the request headers. If there's no request
// we just return a set of empty headers.
func (em *EndpointMeasurement) RequestHeaders() http.Header {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.RequestHeaders
	}
	return http.Header{}
}

// StatusCode returns the response status code. If there's no response
// we just return zero to the caller.
func (em *EndpointMeasurement) StatusCode() int64 {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.StatusCode
	}
	return 0
}

// LocationAsString converts the location URL to string. If the location
// URL is nil, we return an empty string.
func (em *EndpointMeasurement) LocationAsString() string {
	if em.Location != nil {
		return em.Location.String()
	}
	return ""
}

// URLAsString converts the endpoint URL to string. If such an URL
// is nil, we return an empty string.
func (em *EndpointMeasurement) URLAsString() string {
	if em.URL != nil {
		return em.URL.String()
	}
	return ""
}

// BodyLength returns the body length. If there's no body, it returns zero.
func (em *EndpointMeasurement) BodyLength() int64 {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.ResponseBodyLength
	}
	return 0
}

// BodyIsTruncated returns whether the body is truncated. If there's
// no body, this function returns false.
func (em *EndpointMeasurement) BodyIsTruncated() bool {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.ResponseBodyIsTruncated
	}
	return false
}

// SupportsAltSvcHTTP3 indicates whether the response in this EndpointMeasurement
// contains headers claiming the service also supports HTTP3.
func (em *EndpointMeasurement) SupportsAltSvcHTTP3() bool {
	var altsvc string
	if v := em.ResponseHeaders().Get("alt-svc"); v != "" {
		altsvc = v
	}
	// syntax:
	//
	// Alt-Svc: clear
	// Alt-Svc: <protocol-id>=<alt-authority>; ma=<max-age>
	// Alt-Svc: <protocol-id>=<alt-authority>; ma=<max-age>; persist=1
	//
	// multiple entries may be separated by comma.
	//
	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Svc
	entries := strings.Split(altsvc, ",")
	if len(entries) < 1 {
		return false
	}
	for _, entry := range entries {
		parts := strings.Split(entry, ";")
		if len(parts) < 1 {
			continue
		}
		if parts[0] == "h3=\":443\"" {
			return true
		}
	}
	return false
}

// IsHTTPMeasurement returns whether this EndpointMeasurement measures the
// cleartex HTTP protocol using the TCP network.
func (em *EndpointMeasurement) IsHTTPMeasurement() bool {
	return em.URL.Scheme == "http" && em.Network == archival.NetworkTypeTCP
}

// IsHTTPSMeasurement returns whether this EndpointMeasurement measures the
// encrypted HTTPS protocol using the TCP network.
func (em *EndpointMeasurement) IsHTTPSMeasurement() bool {
	return em.URL.Scheme == "https" && em.Network == archival.NetworkTypeTCP
}

// IsHTTP3Measurement returns whether this EndpointMeasurement measures the
// encrypted HTTPS protocol using the QUIC network.
func (em *EndpointMeasurement) IsHTTP3Measurement() bool {
	return em.URL.Scheme == "https" && em.Network == archival.NetworkTypeQUIC
}

func (mx *Measurer) newEndpointMeasurement(
	epnt *EndpointPlan, operation string, err error, responseCookies []*http.Cookie,
	location *url.URL, trace *archival.Trace) *EndpointMeasurement {
	out := &EndpointMeasurement{
		URLMeasurementID: epnt.URLMeasurementID,
		URL:              epnt.URL,
		Network:          epnt.Network,
		Address:          epnt.Address,
		ID:               mx.NextID(),
		Failure:          archival.NewFlatFailure(err),
		FailedOperation:  FlatFailedOperation(operation),
		OrigCookies:      epnt.Cookies,
		NewCookies:       responseCookies,
		Location:         location,
		NetworkEvent:     nil,
		QUICTLSHandshake: nil,
		HTTPRoundTrip:    nil,
	}

	if len(trace.HTTPRoundTrip) > 1 {
		log.Printf("warning: more than one HTTPRoundTrip entry: %+v", trace.HTTPRoundTrip)
	}
	if len(trace.HTTPRoundTrip) == 1 {
		out.HTTPRoundTrip = trace.HTTPRoundTrip[0]
	}

	if len(trace.QUICTLSHandshake) > 1 {
		log.Printf("warning: more than one QUICTLSHandshake entry: %+v", trace.QUICTLSHandshake)
	}
	if len(trace.QUICTLSHandshake) == 1 {
		out.QUICTLSHandshake = trace.QUICTLSHandshake[0]
	}

	if len(trace.TCPConnect) > 1 {
		log.Printf("warning: more than one TCPConnect entry: %+v", trace.TCPConnect)
	}
	if len(trace.TCPConnect) == 1 {
		out.TCPConnect = trace.TCPConnect[0]
	}

	out.NetworkEvent = trace.Network
	return out
}

// MeasureEndpoints measures some endpoints in parallel.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
//
// This function returns to the caller a channel where to read
// measurements from. The channel is closed when done.
func (mx *Measurer) MeasureEndpoints(
	ctx context.Context, epnts ...*EndpointPlan) <-chan *EndpointMeasurement {
	var (
		input  = make(chan *EndpointPlan)
		output = make(chan *EndpointMeasurement)
		done   = make(chan interface{})
	)
	go func() {
		defer close(input)
		for _, epnt := range epnts {
			input <- epnt
		}
	}()
	parallelism := mx.Options.endpointParallelism()
	for i := int64(0); i < parallelism; i++ {
		go func() {
			for epnt := range input {
				output <- mx.measureEndpoint(ctx, epnt)
			}
			done <- true
		}()
	}
	go func() {
		for i := int64(0); i < parallelism; i++ {
			<-done
		}
		close(output)
	}()
	return output
}

func (mx *Measurer) measureEndpoint(ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	switch epnt.URL.Scheme {
	case "tcpconnect":
		return mx.tcpEndpointConnect(ctx, epnt)
	case "tlshandshake":
		return mx.tlsEndpointHandshake(ctx, epnt)
	case "quichandshake":
		return mx.quicEndpointHandshake(ctx, epnt)
	case "http", "https":
		return mx.httpHTTPSOrHTTP3Get(ctx, epnt)
	default:
		return mx.newEndpointMeasurement(epnt, netxlite.TopLevelOperation,
			ErrUnknownURLScheme, nil, nil, &archival.Trace{})
	}
}

func (mx *Measurer) tcpEndpointConnect(
	ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(epnt, operation, err,
		nil, nil, saver.MoveOutTrace())
}

func (mx *Measurer) tlsEndpointHandshake(
	ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	conn, operation, err := mx.tlsEndpointHandshakeWithSaver(ctx, epnt, saver)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(epnt, operation, err,
		nil, nil, saver.MoveOutTrace())
}

func (mx *Measurer) quicEndpointHandshake(
	ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	sess, operation, err := mx.quicEndpointHandshakeWithSaver(ctx, epnt, saver)
	if sess != nil {
		// TODO(bassosimone): close session with correct message
		sess.CloseWithError(0, "")
	}
	return mx.newEndpointMeasurement(epnt, operation, err,
		nil, nil, saver.MoveOutTrace())
}

func (mx *Measurer) httpHTTPSOrHTTP3Get(ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	var (
		resp      *http.Response
		operation string
		err       error
	)
	jar := epnt.newCookieJar() // note: this also sets cookies
	switch epnt.URL.Scheme {
	case "https":
		resp, operation, err = mx.httpsOrHTTP3Get(ctx, epnt, saver, jar)
	case "http":
		resp, operation, err = mx.httpGET(ctx, epnt, saver, jar)
	default:
		return mx.newEndpointMeasurement(epnt, netxlite.TopLevelOperation,
			ErrUnknownURLScheme, nil, nil, &archival.Trace{})
	}
	var (
		responseJar []*http.Cookie
		location    *url.URL
	)
	if resp != nil {
		resp.Body.Close()
		responseJar = jar.Cookies(epnt.URL)
		if loc, err := resp.Location(); err == nil {
			location = loc
		}
	}
	return mx.newEndpointMeasurement(
		epnt,
		operation, err,
		responseJar,
		location,
		saver.MoveOutTrace(),
	)
}

func (mx *Measurer) tcpEndpointConnectWithSaver(ctx context.Context,
	epnt *EndpointPlan, saver *archival.Saver) (net.Conn, string, error) {
	timeout := epnt.Options.tcpConnectTimeout()
	ol := NewOperationLogger(mx.Logger, "[#%d] TCPConnect %s",
		epnt.URLMeasurementID, epnt.Address)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := mx.Library.NewDialerWithoutResolver(saver)
	defer d.CloseIdleConnections()
	conn, err := d.DialContext(ctx, "tcp", epnt.Address)
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.ConnectOperation, err
	}
	conn = saver.WrapConn(conn)
	return conn, "", nil
}

func (mx *Measurer) tlsEndpointHandshakeWithSaver(ctx context.Context,
	epnt *EndpointPlan, saver *archival.Saver) (net.Conn, string, error) {
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	timeout := epnt.Options.tlsHandshakeTimeout()
	tlsConfig := epnt.tlsConfig()
	ol := NewOperationLogger(mx.Logger, "[#%d] TLSHandshake %s with sni=%s",
		epnt.URLMeasurementID, epnt.Address, tlsConfig.ServerName)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	th := saver.WrapTLSHandshaker(mx.TLSHandshaker)
	tlsConn, _, err := th.Handshake(ctx, conn, tlsConfig)
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.TLSHandshakeOperation, err
	}
	return tlsConn, "", nil
}

func (mx *Measurer) quicEndpointHandshakeWithSaver(
	ctx context.Context, epnt *EndpointPlan, saver *archival.Saver) (quic.EarlySession, string, error) {
	timeout := epnt.Options.quicHandshakeTimeout()
	tlsConfig := epnt.tlsConfig()
	ol := NewOperationLogger(mx.Logger, "[#%d] QUICHandshake %s with sni=%s",
		epnt.URLMeasurementID, epnt.Address, tlsConfig.ServerName)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	qd := mx.Library.NewQUICDialerWithoutResolver(saver)
	defer qd.CloseIdleConnections()
	sess, err := qd.DialContext(ctx, "udp", epnt.Address, tlsConfig, &quic.Config{})
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.QUICHandshakeOperation, err
	}
	return sess, "", nil
}

func (mx *Measurer) httpGET(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	defer conn.Close() // we own it
	txp := mx.Library.NewHTTPTransportWithConn(
		saver, conn, epnt.Options.maxHTTPResponseBodySnapshotSize())
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp)
}

func (mx *Measurer) httpsOrHTTP3Get(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	switch epnt.Network {
	case archival.NetworkTypeQUIC:
		return mx.http3GET(ctx, epnt, saver, jar)
	case archival.NetworkTypeTCP:
		return mx.httpsGET(ctx, epnt, saver, jar)
	default:
		return nil, "", ErrUnknownEndpointNetwork
	}
}

func (mx *Measurer) httpsGET(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	conn, operation, err := mx.tlsEndpointHandshakeWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	defer conn.Close() // we own it
	// the cast should always be possible according to nextlite docs
	tlsConn := conn.(model.TLSConn)
	txp := mx.Library.NewHTTPTransportWithTLSConn(saver, tlsConn,
		epnt.Options.maxHTTPSResponseBodySnapshotSizeForEndpointPlan(epnt))
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp)
}

func (mx *Measurer) http3GET(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	sess, operation, err := mx.quicEndpointHandshakeWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	// TODO(bassosimone): close session with correct message
	defer sess.CloseWithError(0, "") // we own it
	txp := mx.Library.NewHTTPTransportWithQUICSess(saver, sess,
		epnt.Options.maxHTTPSResponseBodySnapshotSizeForEndpointPlan(epnt))
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp)
}

func (mx *Measurer) httpTransportDo(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar, txp model.HTTPTransport) (*http.Response, string, error) {
	clnt := mx.newHTTPClientWithoutRedirects(saver, jar, txp)
	defer clnt.CloseIdleConnections()
	return mx.httpClientDo(ctx, clnt, epnt)
}

func (mx *Measurer) httpClientDo(ctx context.Context,
	clnt model.HTTPClient, epnt *EndpointPlan) (*http.Response, string, error) {
	req, err := NewHTTPGetRequest(ctx, epnt.URL.String())
	if err != nil {
		return nil, netxlite.TopLevelOperation, err
	}
	req.Host = epnt.Options.httpHostHeader()
	req.Header = epnt.Options.httpClonedRequestHeaders() //  clone b/c of potential parallel usage
	timeout := epnt.Options.httpGETTimeout()
	ol := NewOperationLogger(mx.Logger, "[#%d] %s %s with %s/%s",
		epnt.URLMeasurementID, req.Method, req.URL.String(), epnt.Address, epnt.Network)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := clnt.Do(req.WithContext(ctx))
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.HTTPRoundTripOperation, err
	}
	return resp, "", nil
}
