package measurex

//
// HTTP
//
// This file contains code for measuring HTTP.
//
//
// Note that this file is not part of ooni/probe-cli.
//

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
)

var (
	// ErrUnknownHTTPEndpointURLScheme means that the given
	// endpoint's URL scheme is neither HTTP nor HTTPS.
	ErrUnknownHTTPEndpointURLScheme = errors.New("unknown HTTPEndpoint.URL.Scheme")

	// ErrUnknownHTTPEndpointNetwork means that the given endpoint's
	// network is of a type that we don't know how to handle.
	ErrUnknownHTTPEndpointNetwork = errors.New("unknown HTTPEndpoint.Network")
)

// HTTPEndpointGet performs a GET request for an HTTP endpoint.
//
// This function WILL NOT follow redirects. If there is a redirect
// you will see it inside the specific database table.
//
// Arguments:
//
// - ctx is the context allowing to timeout the operation;
//
// - epnt is the HTTP endpoint.
//
// Returns a measurement. The returned measurement is empty if
// the endpoint is misconfigured or the URL has an unknown scheme.
func (mx *Measurer) HTTPEndpointGet(
	ctx context.Context, epnt *HTTPEndpoint) *HTTPEndpointMeasurement {
	_, m, _ := mx.httpEndpointGet(ctx, epnt)
	return m
}

// httpEndpointGet implements HTTPEndpointGet.
func (mx *Measurer) httpEndpointGet(
	ctx context.Context, epnt *HTTPEndpoint) (*http.Response, *HTTPEndpointMeasurement, error) {
	jar := epnt.NewCookieJar()
	resp, trace, err := mx.httpEndpointGetReturnTrace(ctx, epnt, jar)
	var responseCookies []*http.Cookie
	if resp != nil {
		responseCookies = jar.Cookies(epnt.URL)
		resp.Body.Close()
	}
	out := mx.newHTTPEndpointMeasurement(
		epnt.URL.String(),
		epnt.Network,
		epnt.Address,
		epnt.Cookies,
		responseCookies,
		trace,
	)
	return resp, out, err
}

// httpEndpointGetReturnTrace implements httpEndpointGet.
//
// This function returns a triple where:
//
// - the first element is a valid response on success a nil response on failure
//
// - the second element is always a valid Trace
//
// - the third element is a nil error on success and an error on failure
func (mx *Measurer) httpEndpointGetReturnTrace(ctx context.Context, epnt *HTTPEndpoint,
	jar http.CookieJar) (resp *http.Response, trace *archival.Trace, err error) {
	saver := archival.NewSaver()
	resp, err = mx.httpEndpointGetWithSaver(ctx, epnt, saver, jar)
	saver.StopCollectingNetworkEvents()
	trace = saver.MoveOutTrace()
	return
}

// HTTPEndpointGetWithSaver is an HTTPEndpointGet that stores the
// events into the given saver.
//
// Caveat: the returned conn will keep saving its I/O events into
// the saver until you stop saving them explicitly.
func (mx *Measurer) HTTPEndpointGetWithSaver(ctx context.Context, epnt *HTTPEndpoint,
	saver *archival.Saver, jar http.CookieJar) (err error) {
	_, err = mx.httpEndpointGetWithSaver(ctx, epnt, saver, jar)
	return
}

// httpEndpointGetWithSaver is an HTTPEndpointGet that stores the
// events into the given Saver.
func (mx *Measurer) httpEndpointGetWithSaver(ctx context.Context, epnt *HTTPEndpoint,
	saver *archival.Saver, jar http.CookieJar) (resp *http.Response, err error) {
	switch epnt.Network {
	case NetworkQUIC:
		resp, err = mx.httpEndpointGetQUIC(ctx, saver, epnt, jar)
	case NetworkTCP:
		resp, err = mx.httpEndpointGetTCP(ctx, saver, epnt, jar)
	default:
		err = ErrUnknownHTTPEndpointNetwork
	}
	return
}

// httpEndpointGetTCP specializes HTTPSEndpointGet for HTTP and HTTPS.
func (mx *Measurer) httpEndpointGetTCP(ctx context.Context,
	saver *archival.Saver, epnt *HTTPEndpoint, jar http.CookieJar) (*http.Response, error) {
	switch epnt.URL.Scheme {
	case "http":
		return mx.httpEndpointGetHTTP(ctx, saver, epnt, jar)
	case "https":
		return mx.httpEndpointGetHTTPS(ctx, saver, epnt, jar)
	default:
		return nil, ErrUnknownHTTPEndpointURLScheme
	}
}

// httpEndpointGetHTTP specializes httpEndpointGetTCP for HTTP.
func (mx *Measurer) httpEndpointGetHTTP(ctx context.Context,
	saver *archival.Saver, epnt *HTTPEndpoint, jar http.CookieJar) (*http.Response, error) {
	conn, err := mx.TCPConnectWithSaver(ctx, saver, epnt.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close() // we own it
	clnt := mx.newHTTPClientWithoutRedirects(saver, jar,
		mx.Library.NewHTTPTransportWithConn(
			saver, conn, mx.MaxHTTPResponseBodySnapshotSize))
	defer clnt.CloseIdleConnections()
	return mx.httpClientDo(ctx, clnt, epnt)
}

// httpEndpointGetHTTPS specializes httpEndpointGetTCP for HTTPS.
func (mx *Measurer) httpEndpointGetHTTPS(ctx context.Context,
	saver *archival.Saver, epnt *HTTPEndpoint, jar http.CookieJar) (*http.Response, error) {
	conn, err := mx.TLSConnectAndHandshakeWithSaver(ctx, saver, epnt.Address, &tls.Config{
		ServerName: epnt.SNI,
		NextProtos: epnt.ALPN,
		RootCAs:    netxlite.NewDefaultCertPool(),
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close() // we own it
	clnt := mx.newHTTPClientWithoutRedirects(saver, jar,
		mx.Library.NewHTTPTransportWithTLSConn(
			saver, conn, mx.MaxHTTPSResponseBodySnapshotSize))
	defer clnt.CloseIdleConnections()
	return mx.httpClientDo(ctx, clnt, epnt)
}

// httpEndpointGetQUIC specializes httpEndpointGetTCP for QUIC.
func (mx *Measurer) httpEndpointGetQUIC(ctx context.Context,
	saver *archival.Saver, epnt *HTTPEndpoint, jar http.CookieJar) (*http.Response, error) {
	sess, err := mx.QUICHandshakeWithSaver(ctx, saver, epnt.Address, &tls.Config{
		ServerName: epnt.SNI,
		NextProtos: epnt.ALPN,
		RootCAs:    netxlite.NewDefaultCertPool(),
	})
	if err != nil {
		return nil, err
	}
	// TODO(bassosimone): close session with correct message
	defer sess.CloseWithError(0, "") // we own it
	clnt := mx.newHTTPClientWithoutRedirects(saver, jar,
		mx.Library.NewHTTPTransportWithQUICSess(
			saver, sess, mx.MaxHTTPSResponseBodySnapshotSize))
	defer clnt.CloseIdleConnections()
	return mx.httpClientDo(ctx, clnt, epnt)
}

// HTTPClientGET performs a GET operation of the given URL
// using the given HTTP client instance.
func (mx *Measurer) HTTPClientGET(
	ctx context.Context, clnt model.HTTPClient, URL *url.URL) (*http.Response, error) {
	return mx.httpClientDo(ctx, clnt, &HTTPEndpoint{
		Domain:  URL.Hostname(),
		Network: "tcp",
		Address: URL.Hostname(),
		SNI:     "",         // not needed
		ALPN:    []string{}, // not needed
		URL:     URL,
		Header:  NewHTTPRequestHeaderForMeasuring(),
	})
}

func (mx *Measurer) httpClientDo(ctx context.Context,
	clnt model.HTTPClient, epnt *HTTPEndpoint) (*http.Response, error) {
	req, err := NewHTTPGetRequest(ctx, epnt.URL.String())
	if err != nil {
		return nil, err
	}
	req.Header = epnt.Header.Clone() // must clone because of potential parallel usage
	timeout := mx.HTTPGETTimeout
	ol := NewOperationLogger(mx.Logger,
		"%s %s with %s/%s", req.Method, req.URL.String(), epnt.Address, epnt.Network)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := clnt.Do(req.WithContext(ctx))
	ol.Stop(err)
	return resp, err
}
