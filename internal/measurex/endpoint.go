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
	"time"

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
	URL *SimpleURL

	// Options contains the options. A nil value implies that we're
	// going to use the default value of each option.
	Options *Options

	// Cookies contains the cookie to use when measuring.
	Cookies []*http.Cookie
}

// Summary returns a string representing the endpoint's plan. Two
// plans are ~same if they have the same summary.
//
// The summary of an endpoint consists of these fields:
//
// - URL
// - Network
// - Address
// - cookies names (sorted)
//
// If the endpoint URL is nil, we return the empty string and
// false; otherwise, a valid string and true.
func (e *EndpointPlan) Summary() (string, bool) {
	return endpointSummary(e.URL, e.Network, e.Address, e.Cookies)
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
	jar.SetCookies(e.URL.ToURL(), e.Cookies)
	return jar
}

// FlatFailedOperation is a flat representation of a failed operation.
type FlatFailedOperation = archival.FlatFailure

// EndpointMeasurement is an endpoint measurement.
type EndpointMeasurement struct {
	// ID is the unique ID of this measurement.
	ID int64

	// URLMeasurementID is the ID of the URLMeasurement that created us.
	URLMeasurementID int64 `json:"-"`

	// URL is the URL this measurement refers to.
	URL *SimpleURL

	// Network is the network of this endpoint.
	Network archival.NetworkType

	// Address is the address of this endpoint.
	Address string

	// Options contains the options used for the measurement.
	Options *Options

	// OrigCookies contains the cookies we originally used.
	OrigCookies []*http.Cookie `json:",omitempty"`

	// Failure is the error that occurred.
	Failure archival.FlatFailure `json:",omitempty"`

	// FailedOperation is the operation that failed.
	FailedOperation FlatFailedOperation `json:",omitempty"`

	// NewCookies contains cookies the next redirection (if any) should use.
	NewCookies []*http.Cookie `json:",omitempty"`

	// Location is the URL we're redirected to (if any).
	Location *url.URL `json:",omitempty"`

	// HTTPTitle is the webpage title (if any).
	HTTPTitle string `json:",omitempty"`

	// NetworkEvent contains network events (if any).
	NetworkEvent []*archival.FlatNetworkEvent `json:",omitempty"`

	// TCPConnect contains the TCP connect event (if any).
	TCPConnect *archival.FlatNetworkEvent `json:",omitempty"`

	// QUICTLSHandshake contains the QUIC/TLS handshake event (if any).
	QUICTLSHandshake *archival.FlatQUICTLSHandshakeEvent `json:",omitempty"`

	// HTTPRoundTrip contains the HTTP round trip event (if any).
	HTTPRoundTrip *archival.FlatHTTPRoundTripEvent `json:",omitempty"`
}

// URLAddressList converts this EndpointMeasurement to an URLAddress list.
func (em *EndpointMeasurement) URLAddressList() ([]*URLAddress, bool) {
	return NewURLAddressList(em.URLMeasurementID, em.URLDomain(),
		[]*DNSLookupMeasurement{}, []*EndpointMeasurement{em})
}

// EndpointMeasurementListToURLAddressList takes in input a list
// of EndpointMeasurement and produces an URLAddressList.
//
// The domain filter selects only the measurements that are
// actually valid for the given domain.
//
// Note: do not use this function if you have better ways of creating
// an URLAddress list, such as, URLMeasurement.URLAddressList.
func EndpointMeasurementListToURLAddressList(
	domain string, eml ...*EndpointMeasurement) ([]*URLAddress, bool) {
	out := []*URLAddress{}
	for _, epnt := range eml {
		ual, good := epnt.URLAddressList()
		if !good {
			continue
		}
		for _, e := range ual {
			if domain != e.Domain {
				continue // not the domain we wanted to see
			}
			out = append(out, e)
		}
	}
	return out, len(out) > 0
}

// TCPQUICConnectRuntime returns the TCP/QUIC connect runtime depending
// on which network is used by this endpoint.
func (em *EndpointMeasurement) TCPQUICConnectRuntime() (out time.Duration) {
	switch em.Network {
	case archival.NetworkTypeQUIC:
		if em.QUICTLSHandshake != nil {
			out = em.QUICTLSHandshake.Finished.Sub(em.QUICTLSHandshake.Started)
		}
	case archival.NetworkTypeTCP:
		if em.TCPConnect != nil {
			out = em.TCPConnect.Finished.Sub(em.TCPConnect.Started)
		}
	}
	return
}

// IsHTTPRedirect returns whether this endpoint contains an HTTP redirect.
func (em *EndpointMeasurement) IsHTTPRedirect() bool {
	return isHTTPRedirect(em.StatusCode())
}

// ResponseBodyTLSH returns the TLSH of the response body or empty string.
func (em *EndpointMeasurement) ResponseBodyTLSH() string {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.ResponseBodyTLSH
	}
	return ""
}

// ResponseBody returns the response body or empty byte array.
func (em *EndpointMeasurement) ResponseBody() []byte {
	if em.HTTPRoundTrip != nil {
		return em.HTTPRoundTrip.ResponseBody
	}
	return []byte{}
}

// RedirectLocationDomain returns the domain of the redirect location.
func (em *EndpointMeasurement) RedirectLocationDomain() string {
	if em.Location != nil {
		return em.Location.Hostname()
	}
	return ""
}

// URLDomain returns the domain used by the URL.
func (em *EndpointMeasurement) URLDomain() string {
	if em.URL != nil {
		return em.URL.Hostname()
	}
	return ""
}

// SeemsLegitimateRedirect works as follows:
//
// 1. if this endpoint does not contain a redirect, return false;
//
// 2. if this endpoint's location is nil, return false;
//
// 3. otherwise returns whether the redirect domain is either equal
// to the original domain or seems a valid sub or super domain.
func (em *EndpointMeasurement) SeemsLegitimateRedirect() bool {
	if !em.IsHTTPRedirect() {
		return false
	}
	if em.Location == nil {
		return false
	}
	orig, location := em.URLDomain(), em.RedirectLocationDomain()
	if orig == location {
		return true // this is a legitimate redirect
	}
	if "www."+orig == location {
		return true // this is also a legitimate redirect
	}
	return orig == "www."+location
}

// UsingAddressIPv6 returns true whether this specific endpoint has
// used an IPv6 destination address, false otherwise.
func (em *EndpointMeasurement) UsingAddressIPv6() (usingIPv6 bool) {
	switch em.Network {
	case archival.NetworkTypeQUIC,
		archival.NetworkTypeTCP:
		usingIPv6 = isEndpointIPv6(em.Address)
	default:
		// nothing
	}
	return
}

// Describe describes this measurement.
func (em *EndpointMeasurement) Describe() string {
	return fmt.Sprintf("[#%d] endpoint measurement #%d for %s using %s",
		em.URLMeasurementID, em.ID, em.URLAsString(), em.EndpointAddress())
}

// Summary returns a string representing the endpoint's summary. Two
// endpoints are ~same if they have the same summary.
//
// The summary of an endpoint consists of these fields:
//
// - URL
// - Network
// - Address
// - original cookies names (sorted)
//
// If the endpoint URL is nil, we return the empty string and
// false; otherwise, a valid string and true.
func (em *EndpointMeasurement) Summary() (string, bool) {
	return endpointSummary(em.URL, em.Network, em.Address, em.OrigCookies)
}

// endpointSummary implements the EndpointMeasurement.Summary
// and EndpointPlan.Summary functions.
func endpointSummary(URL *SimpleURL, network archival.NetworkType,
	address string, cookies []*http.Cookie) (string, bool) {
	var digest []string
	if URL == nil {
		return "", false
	}
	digest = append(digest, CanonicalURLString(URL))
	digest = append(digest, string(network))
	digest = append(digest, address)
	digest = append(digest, SortedSerializedCookiesNames(cookies)...)
	return strings.Join(digest, " "), true
}

// RedirectSummary is a summary of the endpoint's redirect. If there's no
// redirect, we return an empty string and false. Otherwise, we return a
// string that uniquely identifies this redirect and true.
//
// Two redirects are ~same if they have the same redirect summary.
//
// There is a redirect if the code is 301, 302, 303, 307, or 308 and there
// is a non-nil redirect location.
//
// We use these fields for computing the summary:
//
// - redirect location
// - new cookies names (sorted)
func (em *EndpointMeasurement) RedirectSummary() (string, bool) {
	if !isHTTPRedirect(em.StatusCode()) {
		return "", false // skip this entry if it's not a redirect
	}
	if em.Location == nil {
		return "", false // skip this entry if we don't have a valid location
	}
	var digest []string
	digest = append(digest, CanonicalURLString(NewSimpleURL(em.Location)))
	digest = append(digest, SortedSerializedCookiesNames(em.NewCookies)...)
	return strings.Join(digest, " "), true
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

// Scheme returns the URL scheme or an empty string.
func (em *EndpointMeasurement) Scheme() string {
	if em.URL != nil {
		return em.URL.Scheme
	}
	return ""
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

func (mx *Measurer) newEndpointMeasurement(id int64, epnt *EndpointPlan,
	operation string, err error, responseCookies []*http.Cookie,
	location *url.URL, trace *archival.Trace) *EndpointMeasurement {
	out := &EndpointMeasurement{
		ID:               id,
		URLMeasurementID: epnt.URLMeasurementID,
		URL:              epnt.URL,
		Network:          epnt.Network,
		Address:          epnt.Address,
		Options:          epnt.Options,
		OrigCookies:      epnt.Cookies,
		Failure:          archival.NewFlatFailure(err),
		FailedOperation:  FlatFailedOperation(operation),
		NewCookies:       responseCookies,
		Location:         location,
		HTTPTitle:        "",
		NetworkEvent:     nil,
		TCPConnect:       nil,
		QUICTLSHandshake: nil,
		HTTPRoundTrip:    nil,
	}

	if len(trace.HTTPRoundTrip) > 1 {
		log.Printf("warning: more than one HTTPRoundTrip entry: %+v", trace.HTTPRoundTrip)
	}
	if len(trace.HTTPRoundTrip) == 1 {
		out.HTTPRoundTrip = trace.HTTPRoundTrip[0]
		if epnt.Options.httpExtractTitle() {
			out.HTTPTitle = GetWebPageTitle(out.HTTPRoundTrip.ResponseBody)
		}
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
		return mx.newEndpointMeasurement(0, epnt, netxlite.TopLevelOperation,
			ErrUnknownURLScheme, nil, nil, &archival.Trace{})
	}
}

func (mx *Measurer) tcpEndpointConnect(
	ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	id := mx.NextID()
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver, id)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(id, epnt, operation, err,
		nil, nil, saver.MoveOutTrace())
}

func (mx *Measurer) tlsEndpointHandshake(
	ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	id := mx.NextID()
	conn, operation, err := mx.tlsEndpointHandshakeWithSaver(ctx, epnt, saver, id)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(id, epnt, operation, err,
		nil, nil, saver.MoveOutTrace())
}

func (mx *Measurer) quicEndpointHandshake(
	ctx context.Context, epnt *EndpointPlan) *EndpointMeasurement {
	saver := archival.NewSaver()
	id := mx.NextID()
	sess, operation, err := mx.quicEndpointHandshakeWithSaver(ctx, epnt, saver, id)
	if sess != nil {
		// TODO(bassosimone): close session with correct message
		sess.CloseWithError(0, "")
	}
	return mx.newEndpointMeasurement(id, epnt, operation, err,
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
	id := mx.NextID()
	switch epnt.URL.Scheme {
	case "https":
		resp, operation, err = mx.httpsOrHTTP3Get(ctx, epnt, saver, jar, id)
	case "http":
		resp, operation, err = mx.httpGET(ctx, epnt, saver, jar, id)
	default:
		return mx.newEndpointMeasurement(id, epnt, netxlite.TopLevelOperation,
			ErrUnknownURLScheme, nil, nil, &archival.Trace{})
	}
	var (
		responseJar []*http.Cookie
		location    *url.URL
	)
	if resp != nil {
		resp.Body.Close()
		responseJar = jar.Cookies(epnt.URL.ToURL())
		if loc, err := resp.Location(); err == nil {
			location = loc
		}
	}
	return mx.newEndpointMeasurement(id, epnt, operation, err,
		responseJar, location, saver.MoveOutTrace())
}

func (mx *Measurer) tcpEndpointConnectWithSaver(ctx context.Context,
	epnt *EndpointPlan, saver *archival.Saver, id int64) (net.Conn, string, error) {
	timeout := epnt.Options.tcpConnectTimeout()
	ol := NewOperationLogger(mx.Logger, "[#%d] TCPConnect %s",
		id, epnt.Address)
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
	epnt *EndpointPlan, saver *archival.Saver, id int64) (net.Conn, string, error) {
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver, id)
	if err != nil {
		return nil, operation, err
	}
	timeout := epnt.Options.tlsHandshakeTimeout()
	tlsConfig := epnt.tlsConfig()
	ol := NewOperationLogger(mx.Logger, "[#%d] TLSHandshake %s with sni=%s",
		id, epnt.Address, tlsConfig.ServerName)
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

func (mx *Measurer) quicEndpointHandshakeWithSaver(ctx context.Context,
	epnt *EndpointPlan, saver *archival.Saver, id int64) (quic.EarlySession, string, error) {
	timeout := epnt.Options.quicHandshakeTimeout()
	tlsConfig := epnt.tlsConfig()
	ol := NewOperationLogger(mx.Logger, "[#%d] QUICHandshake %s with sni=%s",
		id, epnt.Address, tlsConfig.ServerName)
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
	saver *archival.Saver, jar http.CookieJar, id int64) (*http.Response, string, error) {
	conn, operation, err := mx.tcpEndpointConnectWithSaver(ctx, epnt, saver, id)
	if err != nil {
		return nil, operation, err
	}
	defer conn.Close() // we own it
	txp := mx.Library.NewHTTPTransportWithConn(
		saver, conn, epnt.Options.maxHTTPResponseBodySnapshotSize())
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp, id)
}

func (mx *Measurer) httpsOrHTTP3Get(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar, id int64) (*http.Response, string, error) {
	switch epnt.Network {
	case archival.NetworkTypeQUIC:
		return mx.http3GET(ctx, epnt, saver, jar, id)
	case archival.NetworkTypeTCP:
		return mx.httpsGET(ctx, epnt, saver, jar, id)
	default:
		return nil, "", ErrUnknownEndpointNetwork
	}
}

func (mx *Measurer) httpsGET(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar, id int64) (*http.Response, string, error) {
	conn, operation, err := mx.tlsEndpointHandshakeWithSaver(ctx, epnt, saver, id)
	if err != nil {
		return nil, operation, err
	}
	defer conn.Close() // we own it
	// the cast should always be possible according to nextlite docs
	tlsConn := conn.(model.TLSConn)
	txp := mx.Library.NewHTTPTransportWithTLSConn(saver, tlsConn,
		epnt.Options.maxHTTPSResponseBodySnapshotSizeForEndpointPlan(epnt))
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp, id)
}

func (mx *Measurer) http3GET(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar, id int64) (*http.Response, string, error) {
	sess, operation, err := mx.quicEndpointHandshakeWithSaver(ctx, epnt, saver, id)
	if err != nil {
		return nil, operation, err
	}
	// TODO(bassosimone): close session with correct message
	defer sess.CloseWithError(0, "") // we own it
	txp := mx.Library.NewHTTPTransportWithQUICSess(saver, sess,
		epnt.Options.maxHTTPSResponseBodySnapshotSizeForEndpointPlan(epnt))
	defer txp.CloseIdleConnections()
	return mx.httpTransportDo(ctx, epnt, saver, jar, txp, id)
}

func (mx *Measurer) httpTransportDo(ctx context.Context, epnt *EndpointPlan,
	saver *archival.Saver, jar http.CookieJar, txp model.HTTPTransport, id int64) (*http.Response, string, error) {
	clnt := mx.newHTTPClientWithoutRedirects(saver, jar, txp)
	defer clnt.CloseIdleConnections()
	return mx.httpClientDo(ctx, clnt, epnt, id)
}

func (mx *Measurer) httpClientDo(ctx context.Context,
	clnt model.HTTPClient, epnt *EndpointPlan, id int64) (*http.Response, string, error) {
	req, err := NewHTTPGetRequest(ctx, epnt.URL.String())
	if err != nil {
		return nil, netxlite.TopLevelOperation, err
	}
	req.Host = epnt.Options.httpHostHeader()
	req.Header = epnt.Options.httpClonedRequestHeaders() //  clone b/c of potential parallel usage
	timeout := epnt.Options.httpGETTimeout()
	ol := NewOperationLogger(mx.Logger, "[#%d] %s %s with %s/%s",
		id, req.Method, req.URL.String(), epnt.Address, epnt.Network)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := clnt.Do(req.WithContext(ctx))
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.HTTPRoundTripOperation, err
	}
	return resp, "", nil
}
