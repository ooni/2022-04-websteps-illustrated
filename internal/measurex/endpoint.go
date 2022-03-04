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

// EndpointNetwork is the network of an endpoint.
type EndpointNetwork string

const (
	// NetworkTCP identifies endpoints using TCP.
	NetworkTCP = EndpointNetwork("tcp")

	// NetworkQUIC identifies endpoints using QUIC.
	NetworkQUIC = EndpointNetwork("quic")
)

// EndpointMeasurementPlan is a plan to measure an endpoint.
type EndpointMeasurementPlan struct {
	// URLMeasurementID is the ID of the URLMeasurement that created us.
	URLMeasurementID int64

	// Domain is the endpoint domain (e.g., "dns.google").
	Domain string

	// Network is the network (e.g., "tcp" or "quic").
	Network EndpointNetwork

	// Address is the endpoint address (e.g., "8.8.8.8:443").
	Address string

	// SNI is the SNI to use (only used with URL.scheme == "https").
	SNI string

	// ALPN is the ALPN to use (only used with URL.scheme == "https").
	ALPN []string

	// URL is the endpoint URL.
	URL *url.URL

	// Header contains request headers.
	Header http.Header

	// Cookies contains the cookie to use when measuring.
	Cookies []*http.Cookie
}

func (e *EndpointMeasurementPlan) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: e.SNI,
		NextProtos: e.ALPN,
		RootCAs:    netxlite.NewDefaultCertPool(),
	}
}

func (e *EndpointMeasurementPlan) newCookieJar() http.CookieJar {
	jar := NewCookieJar()
	jar.SetCookies(e.URL, e.Cookies)
	return jar
}

// EndpointMeasurement is an endpoint measurement.
type EndpointMeasurement struct {
	// URLMeasurementID is the ID of the URLMeasurement that created us.
	URLMeasurementID int64

	// URL is the URL this measurement refers to.
	URL *url.URL

	// Network is the network of this endpoint.
	Network EndpointNetwork

	// Address is the address of this endpoint.
	Address string

	// ID is the unique ID of this measurement.
	ID int64

	// Failure is the error that occurred.
	Failure archival.FlatFailure

	// FailedOperation is the operation that failed.
	FailedOperation string

	// Cookies contains cookies the next redirection (if any) should use.
	Cookies []*http.Cookie

	// Location is the URL we're redirected to (if any).
	Location *url.URL

	// StatusCode is the status code (if any).
	StatusCode int64

	// ResponseHeaders contains the response headers (if any).
	ResponseHeaders http.Header

	// An HTTPEndpointMeasurement contains a Trace.
	*archival.Trace
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

// SupportsAltSvcHTTP3 indicates whether the response in this EndpointMeasurement
// contains headers claiming the service also supports HTTP3.
func (em *EndpointMeasurement) SupportsAltSvcHTTP3() bool {
	var altsvc string
	if v := em.ResponseHeaders.Get("alt-svc"); v != "" {
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
	return em.URL.Scheme == "http" && em.Network == NetworkTCP
}

// IsHTTPSMeasurement returns whether this EndpointMeasurement measures the
// encrypted HTTPS protocol using the TCP network.
func (em *EndpointMeasurement) IsHTTPSMeasurement() bool {
	return em.URL.Scheme == "https" && em.Network == NetworkTCP
}

// IsHTTP3Measurement returns whether this EndpointMeasurement measures the
// encrypted HTTPS protocol using the QUIC network.
func (em *EndpointMeasurement) IsHTTP3Measurement() bool {
	return em.URL.Scheme == "https" && em.Network == NetworkQUIC
}

func (mx *Measurer) newEndpointMeasurement(epnt *EndpointMeasurementPlan, operation string,
	err error, responseCookies []*http.Cookie, location *url.URL, statusCode int64,
	responseHeaders http.Header, trace *archival.Trace) *EndpointMeasurement {
	return &EndpointMeasurement{
		URLMeasurementID: epnt.URLMeasurementID,
		URL:              epnt.URL,
		Network:          epnt.Network,
		Address:          epnt.Address,
		ID:               mx.NextID(),
		Failure:          archival.NewFlatFailure(err),
		FailedOperation:  operation,
		Cookies:          responseCookies,
		Location:         location,
		StatusCode:       statusCode,
		ResponseHeaders:  responseHeaders,
		Trace:            trace,
	}
}

// MeasureEndpoints measures some endpoints in parallel.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
//
// This function returns to the caller a channel where to read
// measurements from. The channel is closed when done.
func (mx *Measurer) MeasureEndpoints(ctx context.Context, parallelism int,
	epnts ...*EndpointMeasurementPlan) <-chan *EndpointMeasurement {
	var (
		done   = make(chan interface{})
		input  = make(chan *EndpointMeasurementPlan)
		output = make(chan *EndpointMeasurement)
	)
	go func() {
		defer close(input)
		for _, epnt := range epnts {
			input <- epnt
		}
	}()
	if parallelism <= 0 {
		parallelism = 4
	}
	for i := 0; i < parallelism; i++ {
		go func() {
			for epnt := range input {
				output <- mx.measureEndpoint(ctx, epnt)
			}
			done <- true
		}()
	}
	go func() {
		for i := 0; i < parallelism; i++ {
			<-done
		}
		close(output)
	}()
	return output
}

func (mx *Measurer) measureEndpoint(ctx context.Context, epnt *EndpointMeasurementPlan) *EndpointMeasurement {
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
		return mx.newEndpointMeasurement(epnt,
			netxlite.TopLevelOperation,
			ErrUnknownURLScheme,
			nil, nil, 0, nil,
			&archival.Trace{})
	}
}

func (mx *Measurer) tcpEndpointConnect(
	ctx context.Context, epnt *EndpointMeasurementPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(
		epnt,
		operation, err,
		nil, nil, 0, nil,
		saver.MoveOutTrace(),
	)
}

func (mx *Measurer) tlsEndpointHandshake(
	ctx context.Context, epnt *EndpointMeasurementPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	conn, operation, err := mx.tlsEndpointHandshakeWithSaver(ctx, epnt, saver)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(
		epnt,
		operation, err,
		nil, nil, 0, nil,
		saver.MoveOutTrace(),
	)
}

func (mx *Measurer) quicEndpointHandshake(
	ctx context.Context, epnt *EndpointMeasurementPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	sess, operation, err := mx.quicEndpointHandshakeWithSaver(ctx, epnt, saver)
	if sess != nil {
		// TODO(bassosimone): close session with correct message
		sess.CloseWithError(0, "")
	}
	return mx.newEndpointMeasurement(
		epnt,
		operation, err,
		nil, nil, 0, nil,
		saver.MoveOutTrace(),
	)
}

func (mx *Measurer) httpHTTPSOrHTTP3Get(ctx context.Context, epnt *EndpointMeasurementPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	var (
		resp      *http.Response
		operation string
		err       error
	)
	jar := epnt.newCookieJar()
	switch epnt.URL.Scheme {
	case "https":
		resp, operation, err = mx.httpsOrHTTP3Get(ctx, epnt, saver, jar)
	case "http":
		resp, operation, err = mx.httpGET(ctx, epnt, saver, jar)
	default:
		return mx.newEndpointMeasurement(epnt,
			netxlite.TopLevelOperation,
			ErrUnknownURLScheme,
			nil, nil, 0, nil,
			&archival.Trace{})
	}
	var (
		responseJar     []*http.Cookie
		location        *url.URL
		statusCode      int64
		responseHeaders http.Header
	)
	if resp != nil {
		resp.Body.Close()
		responseJar = jar.Cookies(epnt.URL)
		if loc, err := resp.Location(); err != nil {
			location = loc
		}
		statusCode = int64(resp.StatusCode)
		responseHeaders = resp.Header
	}
	return mx.newEndpointMeasurement(
		epnt,
		operation, err,
		responseJar,
		location,
		statusCode,
		responseHeaders,
		saver.MoveOutTrace(),
	)
}

func (mx *Measurer) tcpEndpointConnectWithSaver(ctx context.Context,
	epnt *EndpointMeasurementPlan, saver *archival.Saver) (net.Conn, string, error) {
	timeout := mx.TCPconnectTimeout
	ol := NewOperationLogger(mx.Logger, "TCPConnect %s", epnt.Address)
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
	epnt *EndpointMeasurementPlan, saver *archival.Saver) (net.Conn, string, error) {
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	timeout := mx.TLSHandshakeTimeout
	ol := NewOperationLogger(mx.Logger, "TLSHandshake %s with sni=%s", epnt.Address, epnt.SNI)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	th := saver.WrapTLSHandshaker(mx.TLSHandshaker)
	tlsConn, _, err := th.Handshake(ctx, conn, epnt.tlsConfig())
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.TLSHandshakeOperation, err
	}
	return tlsConn, "", nil
}

func (mx *Measurer) quicEndpointHandshakeWithSaver(
	ctx context.Context, epnt *EndpointMeasurementPlan, saver *archival.Saver) (quic.EarlySession, string, error) {
	timeout := mx.QUICHandshakeTimeout
	ol := NewOperationLogger(mx.Logger, "QUICHandshake %s with sni=%s", epnt.Address, epnt.SNI)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	qd := mx.Library.NewQUICDialerWithoutResolver(saver)
	defer qd.CloseIdleConnections()
	sess, err := qd.DialContext(ctx, "udp", epnt.Address, epnt.tlsConfig(), &quic.Config{})
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.QUICHandshakeOperation, err
	}
	return sess, "", nil
}

func (mx *Measurer) httpGET(ctx context.Context, epnt *EndpointMeasurementPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	defer conn.Close() // we own it
	txp := mx.Library.NewHTTPTransportWithConn(
		saver, conn, mx.MaxHTTPResponseBodySnapshotSize)
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp)
}

func (mx *Measurer) httpsOrHTTP3Get(ctx context.Context, epnt *EndpointMeasurementPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	switch epnt.Network {
	case NetworkQUIC:
		return mx.http3GET(ctx, epnt, saver, jar)
	case NetworkTCP:
		return mx.httpsGET(ctx, epnt, saver, jar)
	default:
		return nil, "", ErrUnknownEndpointNetwork
	}
}

func (mx *Measurer) httpsGET(ctx context.Context, epnt *EndpointMeasurementPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	conn, operation, err := mx.tlsEndpointHandshakeWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	defer conn.Close() // we own it
	// the cast should always be possible according to nextlite docs
	txp := mx.Library.NewHTTPTransportWithTLSConn(
		saver, conn.(model.TLSConn), mx.MaxHTTPSResponseBodySnapshotSize)
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp)
}

func (mx *Measurer) http3GET(ctx context.Context, epnt *EndpointMeasurementPlan,
	saver *archival.Saver, jar http.CookieJar) (*http.Response, string, error) {
	sess, operation, err := mx.quicEndpointHandshakeWithSaver(ctx, epnt, saver)
	if err != nil {
		return nil, operation, err
	}
	// TODO(bassosimone): close session with correct message
	defer sess.CloseWithError(0, "") // we own it
	txp := mx.Library.NewHTTPTransportWithQUICSess(
		saver, sess, mx.MaxHTTPSResponseBodySnapshotSize)
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp)
}

func (mx *Measurer) httpTransportDo(ctx context.Context, epnt *EndpointMeasurementPlan,
	saver *archival.Saver, jar http.CookieJar, txp model.HTTPTransport) (*http.Response, string, error) {
	clnt := mx.newHTTPClientWithoutRedirects(saver, jar, txp)
	defer clnt.CloseIdleConnections()
	return mx.httpClientDo(ctx, clnt, epnt)
}

func (mx *Measurer) httpClientDo(ctx context.Context,
	clnt model.HTTPClient, epnt *EndpointMeasurementPlan) (*http.Response, string, error) {
	req, err := NewHTTPGetRequest(ctx, epnt.URL.String())
	if err != nil {
		return nil, netxlite.TopLevelOperation, err
	}
	req.Header = epnt.Header.Clone() // must clone because of potential parallel usage
	timeout := mx.HTTPGETTimeout
	ol := NewOperationLogger(mx.Logger,
		"%s %s with %s/%s", req.Method, req.URL.String(), epnt.Address, epnt.Network)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := clnt.Do(req.WithContext(ctx))
	ol.Stop(err)
	return resp, netxlite.HTTPRoundTripOperation, err
}
