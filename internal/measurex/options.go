package measurex

import (
	"net/http"
	"time"
)

//
// Options
//
// This file contains all the options.
//

// Implementation note: if you modify Options double check whether
// added options have an impact onto the endpointSummary.

// Options contains options. Every field in this structure is optional
// and all the methods works as intended when *Options is nil.
type Options struct {
	// ALPN allows to override the QUIC/TLS ALPN we'll use.
	ALPN []string `json:",omitempty"`

	// DNSLookupTimeout is the maximum time we're willing to wait
	// for any DNS lookup to complete.
	DNSLookupTimeout time.Duration `json:",omitempty"`

	// DNSParallelism is the number of parallel goroutines we will
	// use for measuring HTTP/HTTPS/HTTP3 endpoints.
	DNSParallelism int64 `json:",omitempty"`

	// EndpointParallellism is the number of parallel goroutines we will
	// use for measuring HTTP/HTTPS/HTTP3 endpoints.
	EndpointParallelism int64 `json:",omitempty"`

	// HTTPGetTimeout is the maximum time we're willing to wait
	// for any HTTP GET operation to complete.
	HTTPGetTimeout time.Duration `json:",omitempty"`

	// HTTPHostHeader allows to override the Host header we'll use.
	HTTPHostHeader string `json:",omitempty"`

	// HTTPRequestHeaders controls the HTTP request headers we'll use in
	// the first HTTP request. Subsequent requests following redirects
	// will use the same headers of the first request.
	HTTPRequestHeaders http.Header `json:",omitempty"`

	// DoNotInitiallyForceHTTPAndHTTPS controls whether we're going to
	// initially force using both HTTP and HTTPS for the first URL.
	//
	// TODO(bassosimone): per the latest spec, we should rename this
	// variable to become DoNotFollowHTTPAndHTTPS (or maybe we can even
	// find a better name that is even more explanatory).
	DoNotInitiallyForceHTTPAndHTTPS bool `json:",omitempty"`

	// MaxAddressesPerFamily controls the maximum number of IP addresses
	// per family (i.e., A and AAAA) we'll test.
	MaxAddressesPerFamily int64 `json:",omitempty"`

	// MaxCrawlerDepth is the maximum exploration depth. Every different
	// redirection is another depth level. We will stop exploring when we'll
	// have reached the maximum depth.
	MaxCrawlerDepth int64 `json:",omitempty"`

	// MaxHTTPResponseBodySnapshotSize is the maximum response body
	// snapshot size for cleartext requests (HTTP).
	MaxHTTPResponseBodySnapshotSize int64 `json:",omitempty"`

	// MaxHTTPSResponseBodySnapshotSizeConnectivity is the maximum response body
	// snapshot size for encrypted requests (HTTPS/HTTP3), used when we're just
	// ensuring that we can speak with a given HTTPS endpoint.
	MaxHTTPSResponseBodySnapshotSizeConnectivity int64 `json:",omitempty"`

	// MaxHTTPSResponseBodySnapshotSizeThrottling is the maximum response body
	// snapshot size for encrypted requests (HTTPS/HTTP3), used when we want
	// to measure the download speed by downloading a sizable body chunk.
	MaxHTTPSResponseBodySnapshotSizeThrottling int64 `json:",omitempty"`

	// Parent is the parent Options data structure. By setting this field
	// you can layer new Options on top of existing Options.
	Parent *Options `json:",omitempty"`

	// QUICHandshakeTimeout is the maximum time we're willing to wait
	// for any QUIC handshake to complete.
	QUICHandshakeTimeout time.Duration `json:",omitempty"`

	// TCPConnectTimeout is the maximum time we're willing to wait
	// for any TCP connect attempt to complete.
	TCPconnectTimeout time.Duration `json:",omitempty"`

	// TLSHandshakeTimeout is the maximum time we're willing to wait
	// for any TLS handshake to complete.
	TLSHandshakeTimeout time.Duration `json:",omitempty"`

	// SNI allows to override the QUIC/TLS SNI we'll use.
	SNI string `json:",omitempty"`
}

// Chain returns child configured to use the current parent as
// its parent for the purpose of resolving options. If child
// is nil, this function just returns the parent options.
func (parent *Options) Chain(child *Options) *Options {
	if child == nil {
		return parent
	}
	child.Parent = parent
	return child
}

const (
	// DefaultDNSLookupTimeout is the default Options.DNSLookupTimeout value.
	DefaultDNSLookupTimeout = 4 * time.Second

	// DefaultDNSParallelism is the default Options.DNSParallelism value.
	DefaultDNSParallelism = 4

	// DefaultEndpointParallelism is the default Options.EndpointParallelism value.
	DefaultEndpointParallelism = 8

	// DefaultHTTPGETTimeout is the default Options.HTTPGETTimeout value.
	DefaultHTTPGETTimeout = 15 * time.Second

	// DefaultMaxAddressPerFamily is the default value of Options.MaxAddressesPerFamily. For
	// experiments like websteps, where we have a TH, we're actually going to test twice this
	// number when there are many IP addresses per domain, because we're also going to take
	// into account some TH-tested addresses. Going below the recommended value of 2 here
	// is not recommended for websteps. Because websteps uses more than one resolver and
	// because measurex tries to arrange addresses so that we intermix system-resolver and
	// non-system-resolver resolutions, if you use less than two here you are going to
	// only test the first IP address returned by the system resolver, which means you're
	// probably going to miss part of the censorship that's there.
	DefaultMaxAddressPerFamily = 2

	// DefaultMaxCrawlerDepth is the default value of Options.MaxCrawlerDepth.
	DefaultMaxCrawlerDepth = 3

	// DefaultMaxHTTPResponseBodySnapshotSize is the default value
	// of Options.MaxHTTPResponseBodySnapshotSize.
	DefaultMaxHTTPResponseBodySnapshotSize = 1 << 19

	// DefaultMaxHTTPSResponseBodySnapshotSizeConnectivity is the default value
	// of Options.MaxHTTPSResponseBodySnapshotSize when the URL path is "/",
	// where we assume we just want to check connectivity.
	DefaultMaxHTTPSResponseBodySnapshotSizeConnectivity = 1 << 12

	// DefaultMaxHTTPSResponseBodySnapshotSizeThrottling is the default value
	// of Options.MaxHTTPSResponseBodySnapshotSize when the URL path is no "/",
	// where we assume we want to detect signs of throttling.
	DefaultMaxHTTPSResponseBodySnapshotSizeThrottling = 1 << 19

	// DefaultQUICHandshakeTimeout is the default Options.QUICHandshakeTimeout value.
	DefaultQUICHandshakeTimeout = 10 * time.Second

	// DefaultTCPConnectTimeout is the default Options.TCPConnectTimeout value.
	DefaultTCPConnectTimeout = 15 * time.Second

	// DefaultTLSHandshakeTimeout is the default Options.TLSHandshakeTimeout value.
	DefaultTLSHandshakeTimeout = 10 * time.Second
)

// alpn returns the value of the ALPN option or the default.
func (opt *Options) alpn() (v []string) {
	if opt != nil {
		v = opt.ALPN
	}
	if len(v) <= 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.alpn()
	}
	if len(v) <= 0 {
		v = []string{} // consistent representation (needed by caching)
	}
	return
}

// alpnForEndpointPlan returns the ALPN we should be using with this plan.
func (opt *Options) alpnForEndpointPlan(e *EndpointPlan) (v []string) {
	if opt != nil {
		v = opt.ALPN
	}
	if len(v) <= 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.alpnForEndpointPlan(e)
	}
	if len(v) <= 0 && e.URL != nil && e.URL.Scheme == "https" {
		v = ALPNForHTTPSEndpoint(e.Network)
	}
	return
}

// dnsLookupTimeout returns the desired DNS lookup timeout.
func (opt *Options) dnsLookupTimeout() (v time.Duration) {
	if opt != nil {
		v = opt.DNSLookupTimeout
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.dnsLookupTimeout()
	}
	if v == 0 {
		v = DefaultDNSLookupTimeout
	}
	return
}

// dnsParallelism returns the desired level of DNS parallelism.
func (opt *Options) dnsParallelism() (v int64) {
	if opt != nil {
		v = opt.DNSParallelism
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.dnsParallelism()
	}
	if v == 0 {
		v = DefaultDNSParallelism
	}
	return
}

// doNotInitiallyForceHTTPAndHTTPS returns the desired value
// for the DoNotInitiallyForceHTTPAndHTTPS option.
func (opt *Options) doNotInitiallyForceHTTPAndHTTPS() (v bool) {
	if opt != nil {
		v = opt.DoNotInitiallyForceHTTPAndHTTPS
	}
	if !v && opt != nil && opt.Parent != nil {
		v = opt.Parent.doNotInitiallyForceHTTPAndHTTPS()
	}
	return
}

// endpointParallelism returns the desired level of Endpoint parallelism.
func (opt *Options) endpointParallelism() (v int64) {
	if opt != nil {
		v = opt.EndpointParallelism
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.endpointParallelism()
	}
	if v == 0 {
		v = DefaultEndpointParallelism
	}
	return
}

// httpClonedRequestHeaders returns already-cloned request headers.
func (opt *Options) httpClonedRequestHeaders() (v http.Header) {
	if opt != nil {
		v = opt.HTTPRequestHeaders.Clone()
	}
	if len(v) <= 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.httpClonedRequestHeaders()
	}
	if len(v) <= 0 {
		v = NewHTTPRequestHeaderForMeasuring() // no need to clone
	}
	return
}

// httpGETTimeout returns the desired HTTP GET timeout.
func (opt *Options) httpGETTimeout() (v time.Duration) {
	if opt != nil {
		v = opt.HTTPGetTimeout
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.httpGETTimeout()
	}
	if v == 0 {
		v = DefaultHTTPGETTimeout
	}
	return
}

// httpHostHeader returns the desired HTTP Host header.
func (opt *Options) httpHostHeader() (v string) {
	if opt != nil {
		v = opt.HTTPHostHeader
	}
	if v == "" && opt != nil && opt.Parent != nil {
		v = opt.Parent.httpHostHeader()
	}
	return
}

// maxAddressesPerFamily returns the desired maximum number of addresses per family.
func (opt *Options) maxAddressesPerFamily() (v int64) {
	if opt != nil {
		v = opt.MaxAddressesPerFamily
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.maxAddressesPerFamily()
	}
	if v == 0 {
		v = DefaultMaxAddressPerFamily
	}
	return
}

// maxCrawlerDepth returns the desired maximum crawler depth.
func (opt *Options) maxCrawlerDepth() (v int64) {
	if opt != nil {
		v = opt.MaxCrawlerDepth
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.maxCrawlerDepth()
	}
	if v == 0 {
		v = DefaultMaxCrawlerDepth
	}
	return
}

// maxHTTPResponseBodySnapshotSize returns the maximum snapshot
// size for a cleartext HTTP response body.
func (opt *Options) maxHTTPResponseBodySnapshotSize() (v int64) {
	if opt != nil {
		v = opt.MaxHTTPResponseBodySnapshotSize
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.maxHTTPResponseBodySnapshotSize()
	}
	if v == 0 {
		v = DefaultMaxHTTPResponseBodySnapshotSize
	}
	return
}

// maxHTTPSResponseBodySnapshotSizeConnectivity returns the maximum snapshot
// size for an encrypted HTTP response body when measuring connectivity.
func (opt *Options) maxHTTPSResponseBodySnapshotSizeConnectivity() (v int64) {
	if opt != nil {
		v = opt.MaxHTTPSResponseBodySnapshotSizeConnectivity
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.maxHTTPSResponseBodySnapshotSizeConnectivity()
	}
	if v == 0 {
		v = DefaultMaxHTTPSResponseBodySnapshotSizeConnectivity
	}
	return
}

// maxHTTPSResponseBodySnapshotSizeThrottling returns the maximum snapshot
// size for an encrypted HTTP response body when measuring throttling.
func (opt *Options) maxHTTPSResponseBodySnapshotSizeThrottling() (v int64) {
	if opt != nil {
		v = opt.MaxHTTPSResponseBodySnapshotSizeThrottling
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.maxHTTPSResponseBodySnapshotSizeThrottling()
	}
	if v == 0 {
		v = DefaultMaxHTTPSResponseBodySnapshotSizeThrottling
	}
	return
}

// maxHTTPSResponseBodySnapshotSizeForEndpointPlan returns the maximum snapshot
// size for an encrypted HTTP response body, for the given endpoint plan.
func (opt *Options) maxHTTPSResponseBodySnapshotSizeForEndpointPlan(e *EndpointPlan) int64 {
	if e.URL != nil && e.URL.Path != "/" && e.URL.Path != "" {
		return opt.maxHTTPSResponseBodySnapshotSizeThrottling()
	}
	return opt.maxHTTPSResponseBodySnapshotSizeConnectivity()
}

// quicHandshakeTimeout returns the desired QUIC handshake timeout.
func (opt *Options) quicHandshakeTimeout() (v time.Duration) {
	if opt != nil {
		v = opt.QUICHandshakeTimeout
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.quicHandshakeTimeout()
	}
	if v == 0 {
		v = DefaultQUICHandshakeTimeout
	}
	return
}

// sni returns the SNI value or the default.
func (opt *Options) sni() (v string) {
	if opt != nil {
		v = opt.SNI
	}
	if v == "" && opt != nil && opt.Parent != nil {
		v = opt.Parent.sni()
	}
	return
}

// sniForEndpointPlan returns the SNI we should be using with this plan.
func (opt *Options) sniForEndpointPlan(e *EndpointPlan) (v string) {
	if opt != nil {
		v = opt.SNI
	}
	if v == "" && opt != nil && opt.Parent != nil {
		v = opt.Parent.sniForEndpointPlan(e)
	}
	if v == "" && e.URL != nil {
		v = e.URL.Hostname()
	}
	return
}

// tcpConnectTimeout returns the desired TCP connect timeout.
func (opt *Options) tcpConnectTimeout() (v time.Duration) {
	if opt != nil {
		v = opt.TCPconnectTimeout
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.tcpConnectTimeout()
	}
	if v == 0 {
		v = DefaultTCPConnectTimeout
	}
	return
}

// tlsHandshakeTimeout returns the desired TLS handshake timeout.
func (opt *Options) tlsHandshakeTimeout() (v time.Duration) {
	if opt != nil {
		v = opt.TLSHandshakeTimeout
	}
	if v == 0 && opt != nil && opt.Parent != nil {
		v = opt.Parent.tlsHandshakeTimeout()
	}
	if v == 0 {
		v = DefaultTLSHandshakeTimeout
	}
	return
}

// Flatten generates a new Options that contains all the currently
// configured options (or default values) inside it.
func (cur *Options) Flatten() *Options {
	return &Options{
		ALPN:                            cur.alpn(),
		DNSLookupTimeout:                cur.dnsLookupTimeout(),
		DNSParallelism:                  cur.dnsParallelism(),
		EndpointParallelism:             cur.endpointParallelism(),
		HTTPGetTimeout:                  cur.httpGETTimeout(),
		HTTPHostHeader:                  cur.httpHostHeader(),
		HTTPRequestHeaders:              cur.httpClonedRequestHeaders(),
		DoNotInitiallyForceHTTPAndHTTPS: cur.doNotInitiallyForceHTTPAndHTTPS(),
		MaxAddressesPerFamily:           cur.maxAddressesPerFamily(),
		MaxCrawlerDepth:                 cur.maxCrawlerDepth(),
		MaxHTTPResponseBodySnapshotSize: cur.maxHTTPResponseBodySnapshotSize(),
		MaxHTTPSResponseBodySnapshotSizeConnectivity: cur.maxHTTPSResponseBodySnapshotSizeConnectivity(),
		MaxHTTPSResponseBodySnapshotSizeThrottling:   cur.maxHTTPSResponseBodySnapshotSizeThrottling(),
		Parent:               nil,
		QUICHandshakeTimeout: cur.quicHandshakeTimeout(),
		TCPconnectTimeout:    cur.tcpConnectTimeout(),
		TLSHandshakeTimeout:  cur.tlsHandshakeTimeout(),
		SNI:                  cur.sni(),
	}
}
