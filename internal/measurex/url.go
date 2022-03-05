package measurex

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"golang.org/x/net/idna"
)

// URLMeasurement is the (possibly interim) result of measuring an URL.
type URLMeasurement struct {
	// ID is the unique ID of this URLMeasurement.
	ID int64

	// EndpointIDs contains the ID of the EndpointMeasurement(s) that
	// generated this URLMeasurement through redirects.
	EndpointIDs []int64

	// Options contains options. If nil, we'll use default values.
	Options *Options

	// URL is the underlying URL to measure.
	URL *url.URL

	// Cookies contains the list of cookies to use.
	Cookies []*http.Cookie

	// DNS contains a list of DNS measurements.
	DNS []*DNSLookupMeasurement

	// Endpoint contains a list of endpoint measurements.
	Endpoint []*EndpointMeasurement
}

// Domain is the domain inside the input URL.
func (um *URLMeasurement) Domain() string {
	return um.URL.Hostname()
}

// IsHTTP returns whether this URL is HTTP.
func (um *URLMeasurement) IsHTTP() bool {
	return !um.Options.doNotInitiallyForceHTTPAndHTTPS() || um.URL.Scheme == "http"
}

// IsHTTPS returns whether this URL is HTTPS.
func (um *URLMeasurement) IsHTTPS() bool {
	return !um.Options.doNotInitiallyForceHTTPAndHTTPS() || um.URL.Scheme == "https"
}

// NewURLMeasurement creates a new URLMeasurement from a string URL.
func (mx *Measurer) NewURLMeasurement(input string) (*URLMeasurement, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, ErrUnknownURLScheme
	}
	// ensure that we're using the punycoded domain
	if host, err := idna.ToASCII(parsed.Host); err == nil {
		parsed.Host = host
	}
	// if needed normalize the URL path and fragment
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Fragment = ""
	out := &URLMeasurement{
		ID:          mx.NextID(),
		EndpointIDs: []int64{},
		Options:     mx.Options,
		URL:         parsed,
		Cookies:     []*http.Cookie{},
		DNS:         []*DNSLookupMeasurement{},
		Endpoint:    []*EndpointMeasurement{},
	}
	return out, nil
}

// NewDNSLookupPlan creates a NewDNSLookupPlan for this URLMeasurement. The plan calls
// for resolving the domain name inside um.URL using all the given resolvers.
func (um *URLMeasurement) NewDNSLookupPlan(ri []*DNSResolverInfo) *DNSLookupPlan {
	return &DNSLookupPlan{
		URLMeasurementID: um.ID,
		URL:              um.URL,
		Options:          um.Options,
		Resolvers:        ri,
	}
}

// AddFromExternalDNSLookup adds the result of an "external" DNS lookup (i.e., a lookup
// not performed using measurex) to the URLMeasurement.DNS list. You can use this
// functionality, for example, for pre-filling the DNS list with selected IP addresses.
//
// Each IP address will be added to a single entry. We will skip strings that are
// not valid IP addresses representations. The fake entry will use the given
// resolverAddress as the address of the resolver that performed the fake lookup.
//
// The entry will fake an HTTPSvc lookup because that also allows you to include ALPN,
// which you may know, into the generated fake lookup entry. If you don't know the
// ALPN, pass nil as the alpns argument; we will convert it to an empty list for you.
func (um *URLMeasurement) AddFromExternalDNSLookup(
	mx *Measurer, resolverAddress string, alpns []string, addrs ...string) {
	now := time.Now()
	if alpns == nil {
		alpns = []string{}
	}
	var goodAddrs []string
	for _, addr := range addrs {
		if net.ParseIP(addr) == nil {
			log.Printf("AddFromExternalDNSLookup: cannot parse IP: %s", addr)
			continue
		}
		goodAddrs = append(goodAddrs, addr)
	}
	if len(goodAddrs) < 1 {
		// Handle the case where there are no good addresses
		return
	}
	um.DNS = append(um.DNS, &DNSLookupMeasurement{
		ID:               mx.NextID(),
		URLMeasurementID: um.ID,
		Lookup: &archival.FlatDNSLookupEvent{
			ALPNs:           alpns,
			Addresses:       goodAddrs,
			Domain:          um.Domain(),
			Failure:         "",
			Finished:        now,
			LookupType:      archival.DNSLookupTypeHTTPS,
			ResolverAddress: resolverAddress,
			ResolverNetwork: "",
			Started:         now,
		},
		RoundTrip: []*archival.FlatDNSRoundTripEvent{},
	})
}

// URLAddress is an address associated with a given URL.
type URLAddress struct {
	// URLMeasurementID is the ID of the parent URLMeasurement.
	URLMeasurementID int64

	// URL is the original URL.
	URL *url.URL

	// Address is the target IPv4/IPv6 address.
	Address string

	// Flags contains feature flags.
	Flags int64
}

const (
	// urlAddressFlagHTTP3 indicates that a given URL address supports HTTP3.
	urlAddressFlagHTTP3 = 1 << iota

	// urlAddressAlreadyTestedHTTP indicates that this address has already
	// been tested using the cleartext HTTP protocol.
	urlAddressAlreadyTestedHTTP

	// urlAddressAlreadyTestedHTTPS indicates that this address has already
	// been tested using the encrypted HTTPS protocol.
	urlAddressAlreadyTestedHTTPS

	// urlAddressAlreadyTestedHTTP3 indicates that this address has already
	// been tested using the encrypted HTTP3 protocol.
	urlAddressAlreadyTestedHTTP3
)

// Domain returns the domain for which the address should be valid. Because the
// DNS may be lying to us, we cannot be sure about that, though.
func (ua *URLAddress) Domain() string {
	return ua.URL.Hostname()
}

// SupportsHTTP3 returns whether we think this address supports HTTP3.
func (ua *URLAddress) SupportsHTTP3() bool {
	return (ua.Flags & urlAddressFlagHTTP3) != 0
}

// AlreadyTestedHTTP returns whether we've already tested this IP address using HTTP.
func (ua *URLAddress) AlreadyTestedHTTP() bool {
	return (ua.Flags & urlAddressAlreadyTestedHTTP) != 0
}

// AlreadyTestedHTTPS returns whether we've already tested this IP address using HTTPS.
func (ua *URLAddress) AlreadyTestedHTTPS() bool {
	return (ua.Flags & urlAddressAlreadyTestedHTTPS) != 0
}

// AlreadyTestedHTTP3 returns whether we've already tested this IP address using HTTP3.
func (ua *URLAddress) AlreadyTestedHTTP3() bool {
	return (ua.Flags & urlAddressAlreadyTestedHTTP3) != 0
}

// URLAddressList generates a list of URLAddresses based on DNS lookups. The boolean
// return value indicates whether we have at least one IP address in the result.
func (um *URLMeasurement) URLAddressList() ([]*URLAddress, bool) {
	uniq := make(map[string]int64)
	// start searching into the DNS lookup results.
	for _, dns := range um.DNS {
		var flags int64
		if dns.SupportsHTTP3() {
			flags |= urlAddressFlagHTTP3
		}
		for _, addr := range dns.Addresses() {
			if net.ParseIP(addr) == nil {
				// Skip CNAMEs in case they slip through.
				log.Printf("cannot parse %+v inside um.DNS as IP address", addr)
				continue
			}
			uniq[addr] |= flags
		}
	}
	// continue searching into HTTP responses.
	for _, epnt := range um.Endpoint {
		ipAddr, err := epnt.IPAddress()
		if err != nil {
			// This may actually be an IPv6 address with explicit scope
			log.Printf("cannot parse %+v inside epnt.Address as IP address", epnt.Address)
			continue
		}
		if epnt.IsHTTPMeasurement() {
			uniq[ipAddr] |= urlAddressAlreadyTestedHTTP
		}
		if epnt.IsHTTPSMeasurement() {
			uniq[ipAddr] |= urlAddressAlreadyTestedHTTPS
		}
		if epnt.IsHTTP3Measurement() {
			uniq[ipAddr] |= urlAddressAlreadyTestedHTTP3
		}
		if epnt.SupportsAltSvcHTTP3() {
			uniq[ipAddr] |= urlAddressFlagHTTP3
		}
	}
	// finally build the result.
	out := make([]*URLAddress, 0, 8)
	for addr, flags := range uniq {
		out = append(out, &URLAddress{
			URLMeasurementID: um.ID,
			URL:              um.URL,
			Address:          addr,
			Flags:            flags,
		})
	}
	return out, len(out) > 0
}

const (
	// EndpointPlanningExcludeBogons excludes bogons from NewEndpointPlan's planning.
	EndpointPlanningExcludeBogons = 1 << iota
)

// NewEndpointPlan creates a new plan for measuring all the endpoints that
// have not been measured yet in the current URLMeasurement.
//
// Note that the returned list will include HTTP, HTTPS, and HTTP3 plans
// related to the original URL regardless of its scheme.
//
// The flags argument allows to specify flags that modify the planning
// algorithm. The EndpointPlanningExcludeBogons flag is such that we
// will not include any bogon IP address into the returned plan.
func (um *URLMeasurement) NewEndpointPlan(flags int64) ([]*EndpointPlan, bool) {
	addrs, _ := um.URLAddressList()
	out := make([]*EndpointPlan, 0, 8)
	familyCounter := make(map[string]int64)
	for _, addr := range addrs {
		if (flags&EndpointPlanningExcludeBogons) != 0 && netxlite.IsBogon(addr.Address) {
			// Exclude bogons from planning if we're requested to do so.
			continue
		}

		family := "A"
		if strings.Contains(addr.Address, ":") {
			family = "AAAA"
		}
		if familyCounter[family] >= um.Options.maxAddressesPerFamily() {
			// Do not add more than N IP addrs for each address family.
			continue
		}
		familyCounter[family] += 1

		if um.IsHTTP() && !addr.AlreadyTestedHTTP() {
			plan, err := um.newEndpointPlan(archival.NetworkTypeTCP, addr.Address, "http")
			if err != nil {
				log.Printf("cannot make plan: %s", err.Error())
				continue
			}
			out = append(out, plan)
		}

		if um.IsHTTPS() && !addr.AlreadyTestedHTTPS() {
			plan, err := um.newEndpointPlan(archival.NetworkTypeTCP, addr.Address, "https")
			if err != nil {
				log.Printf("cannot make plan: %s", err.Error())
				continue
			}
			out = append(out, plan)
		}

		if um.IsHTTPS() && addr.SupportsHTTP3() && !addr.AlreadyTestedHTTP3() {
			plan, err := um.newEndpointPlan(archival.NetworkTypeQUIC, addr.Address, "https")
			if err != nil {
				log.Printf("cannot make plan: %s", err.Error())
				continue
			}
			out = append(out, plan)
		}
	}
	return out, len(out) > 0
}

// newEndpointPlan is a factory for creating an endpoint plan.
func (um *URLMeasurement) newEndpointPlan(
	network archival.NetworkType, address, scheme string) (*EndpointPlan, error) {
	URL := newURLWithScheme(um.URL, scheme)
	epnt, err := urlMakeEndpoint(URL, address)
	if err != nil {
		return nil, err
	}
	out := &EndpointPlan{
		URLMeasurementID: um.ID,
		Domain:           um.Domain(),
		Network:          network,
		Address:          epnt,
		URL:              URL,
		Options:          um.Options,
		Cookies:          um.Cookies,
	}
	return out, nil
}

// newURLWithScheme creates a copy of an URL with a different scheme.
func newURLWithScheme(URL *url.URL, scheme string) *url.URL {
	return &url.URL{
		Scheme:      scheme,
		Opaque:      URL.Opaque,
		User:        URL.User,
		Host:        URL.Host,
		Path:        URL.Path,
		RawPath:     URL.RawPath,
		ForceQuery:  URL.ForceQuery,
		RawQuery:    URL.RawQuery,
		Fragment:    URL.Fragment,
		RawFragment: URL.RawFragment,
	}
}

// urlMakeEndpoint makes a level-4 endpoint given the address and either the URL scheme
// or the explicit port provided inside the URL.
func urlMakeEndpoint(URL *url.URL, address string) (string, error) {
	port, err := PortFromURL(URL)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(address, port), nil
}

// urlRedirectPolicy determines the policy for computing redirects.
type urlRedirectPolicy interface {
	// Summary returns a string summarizing the given endpoint. This function
	// must return false if the endpoint is not relevant to the policy with
	// which we're currently computing redirects.
	Summary(epnt *EndpointMeasurement) (string, bool)
}

// urlRedirectPolicyDefault is the default urlRedirectPolicy.
type urlRedirectPolicyDefault struct{}

// Summary implements urlRedirectPolicy.Summary.
func (*urlRedirectPolicyDefault) Summary(epnt *EndpointMeasurement) (string, bool) {
	switch epnt.StatusCode() {
	case 301, 302, 303, 306, 307:
	default:
		return "", false // skip this entry if it's not a redirect
	}
	if epnt.Location == nil {
		return "", false // skip this entry if we don't have a valid location
	}
	// If this URL is HTTPS, just ignore conflicting cookies
	if epnt.URL.Scheme == "https" {
		return epnt.Location.String(), true
	}
	// If there are no cookies, likewise
	if len(epnt.NewCookies) <= 0 {
		return epnt.Location.String(), true
	}
	// Otherwise, account for cookies
	summary := make([]string, 0, 4)
	for _, cookie := range epnt.NewCookies {
		summary = append(summary, cookie.String())
	}
	sort.Strings(summary)
	summary = append(summary, epnt.Location.String())
	return strings.Join(summary, " "), true
}

// Redirects returns all the redirects seen in this URLMeasurement as a
// list of follow-up URLMeasurement instances. This function will return
// false if the returned list of follow-up measurements is empty.
func (mx *Measurer) Redirects(cur *URLMeasurement) ([]*URLMeasurement, bool) {
	return mx.redirects(cur, &urlRedirectPolicyDefault{})
}

func (mx *Measurer) redirects(
	cur *URLMeasurement, policy urlRedirectPolicy) ([]*URLMeasurement, bool) {
	uniq := make(map[string]*URLMeasurement)
	for _, epnt := range cur.Endpoint {
		summary, good := policy.Summary(epnt)
		if !good {
			// We should skip this endpoint
			continue
		}
		if epnt.Location == nil {
			// Safety net: don't try to redirect if we don't know where to
			continue
		}
		next, good := uniq[summary]
		if !good {
			requestHeaders := mx.newHeadersForRedirect(
				epnt.Location, epnt.RequestHeaders())
			next = &URLMeasurement{
				ID:          mx.NextID(),
				EndpointIDs: []int64{},
				URL:         epnt.Location,
				Cookies:     epnt.NewCookies,
				Options: cur.Options.Chain(&Options{
					// Note: all other fields intentionally left empty. We do not
					// want to continue following HTTP and HTTPS after we have done
					// that for the initial URL we needed to measure.
					DoNotInitiallyForceHTTPAndHTTPS: true,
					HTTPRequestHeaders:              requestHeaders,
				}),
				DNS:      []*DNSLookupMeasurement{},
				Endpoint: []*EndpointMeasurement{},
			}
			uniq[summary] = next
		}
		next.EndpointIDs = append(next.EndpointIDs, epnt.ID)
	}
	out := make([]*URLMeasurement, 0, 8)
	for _, next := range uniq {
		out = append(out, next)
	}
	return out, len(out) > 0
}

// newHeadersForRedirect builds new headers for a redirect.
func (mx *Measurer) newHeadersForRedirect(location *url.URL, orig http.Header) http.Header {
	out := http.Header{}
	for key, values := range orig {
		out[key] = values
	}
	if location != nil { // just in case
		out.Set("Referer", location.String())
	}
	return out
}

// URLRedirectDeque is the type we use to manage the redirection
// queue and to follow a reasonable number of redirects.
type URLRedirectDeque struct {
	// depth counts the depth
	depth int64

	// logger is the logger to use.
	logger model.Logger

	// mem contains the URLs we've already visited.
	mem map[string]bool

	// mu provides mutual exclusion.
	mu sync.Mutex

	// options contains options.
	options *Options

	// q contains the current deque
	q []*URLMeasurement
}

// NewURLRedirectDeque creates an URLRedirectDeque.
func (mx *Measurer) NewURLRedirectDeque(logger model.Logger) *URLRedirectDeque {
	return &URLRedirectDeque{
		depth:   0,
		logger:  logger,
		mem:     map[string]bool{},
		mu:      sync.Mutex{},
		options: mx.Options,
		q:       []*URLMeasurement{},
	}
}

// reprURL returns a representation of the given URL that should be
// more canonical than the random URLs returned by web services.
//
// We need as canonical as possible URLs in URLRedirectDeque because
// their string representation is used to decide whether we need to
// follow redirects or not.
//
// SPDX-License-Identifier: MIT
//
// Adapted from: https://github.com/sekimura/go-normalize-url.
func (r *URLRedirectDeque) reprURL(URL *url.URL) string {
	u := newURLWithScheme(URL, URL.Scheme)
	// TODO(bassosimone): canonicalize path if needed?
	// TODO(bassosimone): how about IDNA?
	v := u.Query()
	u.RawQuery = v.Encode()
	u.RawQuery, _ = url.QueryUnescape(u.RawQuery)
	return u.String()
}

// String returns a string representation of the deque.
func (r *URLRedirectDeque) String() string {
	defer r.mu.Unlock()
	r.mu.Lock()
	var out []string
	for _, entry := range r.q {
		out = append(out, r.reprURL(entry.URL))
	}
	return fmt.Sprintf("%+v", out)
}

// Append appends one or more URLMeasurement to the right of the deque.
func (r *URLRedirectDeque) Append(um ...*URLMeasurement) {
	defer r.mu.Unlock()
	r.mu.Lock()
	r.q = append(r.q, um...)
}

// RememberVisitedURLs register the URLs we've already visited so that
// we're not going to visit them again.
func (r *URLRedirectDeque) RememberVisitedURLs(um *URLMeasurement) {
	defer r.mu.Unlock()
	r.mu.Lock()
	for _, epnt := range um.Endpoint {
		r.mem[r.reprURL(epnt.URL)] = true
	}
}

// PopLeft removes the first element in the redirect deque. Returns true
// if we returned an element and false when the deque is empty.
func (r *URLRedirectDeque) PopLeft() (*URLMeasurement, bool) {
	defer r.mu.Unlock()
	r.mu.Lock()
	if r.depth > r.options.maxCrawlerDepth() {
		r.logger.Info("👋 reached maximum crawler depth")
		return nil, false
	}
	for len(r.q) > 0 {
		um := r.q[0]
		r.q = r.q[1:]
		if repr := r.reprURL(um.URL); r.mem[repr] {
			r.logger.Infof("🧐 skip already visited URL: %s", repr)
			continue
		}
		r.depth++ // we increment the depth when we _remove_ and measure
		return um, true
	}
	return nil, false
}

// Depth returns the number or redirects we followed so far.
func (r *URLRedirectDeque) Depth() int64 {
	defer r.mu.Unlock()
	r.mu.Lock()
	return r.depth
}
