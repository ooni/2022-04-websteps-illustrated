package measurex

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/ooni/2022-04-websteps-illustrated/internal/archival"
	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
	"golang.org/x/net/idna"
)

// SimpleURL is a simpler URL representation.
type SimpleURL struct {
	// Scheme is the URL scheme.
	Scheme string `json:",omitempty"`

	// Host is the host (possily containing a port)
	Host string

	// Path is the URL path.
	Path string `json:",omitempty"`

	// RawQuery contains the unparsed query.
	RawQuery string `json:",omitempty"`
}

// NewSimpleURL creates a simple URL from an URL.
func NewSimpleURL(URL *url.URL) (out *SimpleURL) {
	if URL != nil {
		out = &SimpleURL{
			Scheme:   URL.Scheme,
			Host:     URL.Host,
			Path:     URL.Path,
			RawQuery: URL.RawQuery,
		}
	}
	return
}

// Hostname is like url.URL.Hostname.
func (su *SimpleURL) Hostname() string {
	return su.ToURL().Hostname()
}

// Port is like url.URL.Port.
func (su *SimpleURL) Port() string {
	return su.ToURL().Port()
}

// String is like url.URL.String.
func (su *SimpleURL) String() string {
	return su.ToURL().String()
}

// Query is like url.URL.Query.
func (su *SimpleURL) Query() url.Values {
	return su.ToURL().Query()
}

// ToURL converts SimpleURL back to stdlib URL.
func (su *SimpleURL) ToURL() *url.URL {
	return &url.URL{
		Scheme:      su.Scheme,
		Opaque:      "",
		User:        nil,
		Host:        su.Host,
		Path:        su.Path,
		RawPath:     "",
		ForceQuery:  false,
		RawQuery:    su.RawQuery,
		Fragment:    "",
		RawFragment: "",
	}
}

// Clone creates a copy of this SimpleURL.
func (su *SimpleURL) Clone() *SimpleURL {
	return &SimpleURL{
		Scheme:   su.Scheme,
		Host:     su.Host,
		Path:     su.Path,
		RawQuery: su.RawQuery,
	}
}

// ParseSimpleURL parses a simple URL and returns it.
func ParseSimpleURL(URL string) (*SimpleURL, error) {
	parsed, err := url.Parse(URL)
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
	return NewSimpleURL(parsed), nil
}

// URLMeasurement is the (possibly interim) result of measuring an URL.
type URLMeasurement struct {
	// ID is the unique ID of this URLMeasurement.
	ID int64

	// EndpointIDs contains the ID of the EndpointMeasurement(s) that
	// generated this URLMeasurement through redirects.
	EndpointIDs []int64 `json:",omitempty"`

	// Options contains options. If nil, we'll use default values.
	Options *Options `json:",omitempty"`

	// URL is the underlying URL to measure.
	URL *SimpleURL

	// Cookies contains the list of cookies to use.
	Cookies []*http.Cookie `json:",omitempty"`

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
	parsed, err := ParseSimpleURL(input)
	if err != nil {
		return nil, err
	}
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

// NewDNSLookupPlans is a convenience function for calling the NewDNSLookupPlans
// free function in the context of this URLMeasurement.
func (um *URLMeasurement) NewDNSLookupPlans(
	flags int64, ri ...*DNSResolverInfo) []*DNSLookupPlan {
	return newDNSLookupPlans(um.ID, um.URL.Hostname(), um.Options, flags, ri...)
}

// AddFromExternalDNSLookup adds the result of an "external" DNS lookup (i.e., a lookup
// not performed using measurex) to the URLMeasurement.DNS list. You can use this
// functionality, for example, for pre-filling the DNS list with selected IP addresses.
//
// Each IP address will be added to a single entry. We will skip strings that are
// not valid IP addresses representations. The fake entry will use the given
// resolver network and address (you may want to, e.g., set them to "probe" or "th").
//
// The entry will fake an HTTPSvc lookup because that also allows you to include ALPN,
// which you may know, into the generated fake lookup entry. If you don't know the
// ALPN, pass nil as the alpns argument; we will convert it to an empty list for you.
//
// If there are duplicate entries, they will be collapsed by this function.
func (um *URLMeasurement) AddFromExternalDNSLookup(mx AbstractMeasurer,
	resolverNetwork, resolverAddress string, alpns []string, addrs ...string) {
	if alpns == nil {
		alpns = []string{}
	}
	var goodAddrs []string
	for _, addr := range StringListSortUniq(addrs) {
		if net.ParseIP(addr) == nil {
			logcat.Shrugf("[mx] AddFromExternalDNSLookup: cannot parse IP: %s", addr)
			continue
		}
		goodAddrs = append(goodAddrs, addr)
	}
	if len(goodAddrs) < 1 {
		// Handle the case where there are no good addresses
		return
	}
	um.DNS = append(um.DNS, newFakeHTTPSSvcDNSLookupMeasurement(
		um.ID, mx, archival.NetworkType(resolverNetwork), resolverAddress,
		um.Domain(), alpns, goodAddrs,
	))
}

// URLAddress is an address associated with a given URL.
type URLAddress struct {
	// URLMeasurementID is the ID of the parent URLMeasurement.
	URLMeasurementID int64

	// Address is the target IPv4/IPv6 address.
	Address string

	// Domain is the domain of the URL.
	Domain string

	// Flags contains URL flags.
	Flags int64
}

// URLAddressListToString transforms an URLAddressList to a
// flat list of IP addresses, which is useful for logging.
func URLAddressListToString(ual []*URLAddress) string {
	v := []string{}
	for _, ua := range ual {
		v = append(v, ua.Address)
	}
	return strings.Join(v, ", ")
}

// Clone creates a clone of this URLAddressList.
func (ua *URLAddress) Clone() *URLAddress {
	return &URLAddress{
		URLMeasurementID: ua.URLMeasurementID,
		Address:          ua.Address,
		Domain:           ua.Domain,
		Flags:            ua.Flags,
	}
}

// urlAddressWithIndex is an helper struct used by the
// MergeURLAddressListStable algorithm.
type urlAddressWithIndex struct {
	idx int
	ua  *URLAddress
}

// MergeURLAddressListStable takes in input a list of []*URLAddress and it
// returns a new list where each IP address appears just once and the flags
// of all its duplicates in input have been merged. The first step of the
// algorithm is creating a unique list concatenating all the lists provided
// in input. Then, it will proceed to remove duplicates. In doing so, it
// will preserve the original order in which unique IP addresses appear in
// the concatenated list. For example, if IP A appears before IP B in the
// concatenated list, the same will hold for the return list. Note that
// the elements of the returned list are clones of the original. So this
// is a non-destructive and data-race-safe operation.
func MergeURLAddressListStable(in ...[]*URLAddress) []*URLAddress {
	uas := []*URLAddress{}
	for _, ua := range in {
		uas = append(uas, ua...)
	}
	m := make(map[string]*urlAddressWithIndex)
	for idx, ua := range uas {
		if e, ok := m[ua.Address]; ok {
			e.ua.Flags |= ua.Flags
			continue
		}
		m[ua.Address] = &urlAddressWithIndex{
			idx: idx,
			ua:  ua.Clone(), // allow for safe mutation
		}
	}
	sortable := []*urlAddressWithIndex{}
	for _, value := range m {
		sortable = append(sortable, value)
	}
	sort.SliceStable(sortable, func(i, j int) bool {
		return sortable[i].idx < sortable[j].idx
	})
	out := []*URLAddress{}
	for _, e := range sortable {
		out = append(out, e.ua)
	}
	return out
}

// URLAddressListDiff is the diff of two []*URLAddress.
type URLAddressListDiff struct {
	// ModifiedFlags contains all the entries in A that have different
	// flags compared to the respective entries in B.
	ModifiedFlags []*URLAddress

	// NewEntries contains all the entries in A that do not appear in B.
	NewEntries []*URLAddress
}

// NewURLAddressListDiff takes in input two []*URLAddress A and B and returns
// in output all the elements of A that do not appear in B or appear in B with
// different flags than they appear in A. If the two lists are equal, we just
// return to the caller an empty diff. The output will always be a valid struct
// containing lists with pointers to the original matching elements in the A
// list. The relative order of elements in the lists of the returned diff struct
// is consistent with the order they appear in the A list.
func NewURLAddressListDiff(A, B []*URLAddress) *URLAddressListDiff {
	m := map[string]*URLAddress{}
	for _, b := range B {
		m[b.Address] = b
	}
	out := &URLAddressListDiff{}
	for _, a := range A {
		if b, ok := m[a.Address]; ok {
			if a.Flags != b.Flags {
				out.ModifiedFlags = append(out.ModifiedFlags, a)
			}
			continue
		}
		out.NewEntries = append(out.NewEntries, a)
	}
	return out
}

const (
	// URLAddressSupportsHTTP3 indicates that a given URL address supports HTTP3.
	URLAddressSupportsHTTP3 = 1 << iota

	// URLAddressAlreadyTestedHTTP indicates that this address has already
	// been tested using the cleartext HTTP protocol.
	URLAddressAlreadyTestedHTTP

	// URLAddressAlreadyTestedHTTPS indicates that this address has already
	// been tested using the encrypted HTTPS protocol.
	URLAddressAlreadyTestedHTTPS

	// URLAddressAlreadyTestedHTTP3 indicates that this address has already
	// been tested using the encrypted HTTP3 protocol.
	URLAddressAlreadyTestedHTTP3

	// URLAddressSystemResolver indicates that this entry has been
	// discovered through the system resolver.
	URLAddressSystemResolver
)

// SupportsHTTP3 returns whether we think this address supports HTTP3.
func (ua *URLAddress) SupportsHTTP3() bool {
	return (ua.Flags & URLAddressSupportsHTTP3) != 0
}

// AlreadyTestedHTTP returns whether we've already tested this IP address using HTTP.
func (ua *URLAddress) AlreadyTestedHTTP() bool {
	return (ua.Flags & URLAddressAlreadyTestedHTTP) != 0
}

// AlreadyTestedHTTPS returns whether we've already tested this IP address using HTTPS.
func (ua *URLAddress) AlreadyTestedHTTPS() bool {
	return (ua.Flags & URLAddressAlreadyTestedHTTPS) != 0
}

// AlreadyTestedHTTP3 returns whether we've already tested this IP address using HTTP3.
func (ua *URLAddress) AlreadyTestedHTTP3() bool {
	return (ua.Flags & URLAddressAlreadyTestedHTTP3) != 0
}

// NewURLAddressList generates a list of URLAddresses based on DNS lookups and
// Endpoint measurements, all relative to the given ID. We'll _only_ include into
// the result the IP addresses relative to the given domain. The boolean
// return value indicates whether we have at least one IP address in the result.
func NewURLAddressList(ID int64, domain string, dns []*DNSLookupMeasurement,
	endpoint []*EndpointMeasurement) ([]*URLAddress, bool) {
	uniq := newOrderedMapStringToFlags()
	// 1. start searching into the DNS lookup results.
	for _, dns := range dns {
		if domain != dns.Domain() {
			continue // we're not including unrelated domains
		}
		var flags int64
		if dns.SupportsHTTP3() {
			flags |= URLAddressSupportsHTTP3
		}
		if dns.ResolverNetwork() == archival.NetworkTypeSystem {
			flags |= URLAddressSystemResolver
		}
		for _, addr := range dns.Addresses() {
			if net.ParseIP(addr) == nil {
				// Skip CNAMEs in case they slip through.
				logcat.Bugf("[mx] NewURLAddressList: cannot parse IP: %s", addr)
				continue
			}
			uniq.bitwiseOrForKey(addr, flags)
		}
	}
	// 2. continue searching into HTTP responses.
	for _, epnt := range endpoint {
		if domain != epnt.URLDomain() {
			continue // we're not including unrelated domains
		}
		ipAddr := epnt.IPAddress()
		if ipAddr == "" {
			// This may actually be an IPv6 address with explicit scope
			logcat.Bugf("[mx] NewURLAddressList: cannot parse IP: %s", ipAddr)
			continue
		}
		if epnt.IsHTTPMeasurement() {
			uniq.bitwiseOrForKey(ipAddr, URLAddressAlreadyTestedHTTP)
		}
		if epnt.IsHTTPSMeasurement() {
			uniq.bitwiseOrForKey(ipAddr, URLAddressAlreadyTestedHTTPS)
		}
		if epnt.IsHTTP3Measurement() {
			uniq.bitwiseOrForKey(ipAddr, URLAddressAlreadyTestedHTTP3)
		}
		if epnt.SupportsAltSvcHTTP3() {
			uniq.bitwiseOrForKey(ipAddr, URLAddressSupportsHTTP3)
		}
	}
	// 3. finally build the result.
	out := make([]*URLAddress, 0, 8)
	for _, addr := range uniq.orderedKeys() {
		out = append(out, &URLAddress{
			URLMeasurementID: ID,
			Address:          addr,
			Domain:           domain,
			Flags:            uniq.get(addr),
		})
	}
	// 4. rearrange and return
	out = rearrangeAddresses(out)
	return out, len(out) > 0
}

// rearrangeAddresses splits the set of known IP addresses into two sets: the one
// discovered using the system resolver and the others. Then, it returns in output
// a new set of IP addresses where we intermix entries from the system resolver
// with other entries. This ensures we test at least one entry from the system resolver
// and one other entry if we have at least two addresses per family.
//
// This spreading algorithm is important to ensure that:
//
// 1. we test at least one IP address from the system resolver, which may be
// the only censored resolver in a bunch of cases;
//
// 2. we test at least another address, because we want to give a chance to
// other resolvers and see what they return.
func rearrangeAddresses(ual []*URLAddress) []*URLAddress {
	// 1. divide the input in two sets
	system := []*URLAddress{}
	other := []*URLAddress{}
	for _, entry := range ual {
		if (entry.Flags & URLAddressSystemResolver) != 0 {
			system = append(system, entry)
		} else {
			other = append(other, entry)
		}
	}
	// 2. zip the two sets together
	out := []*URLAddress{}
	for si, oi := 0, 0; len(out) < len(system)+len(other); {
		if si < len(system) {
			out = append(out, system[si])
			si++
		}
		if oi < len(other) {
			out = append(out, other[oi])
			oi++
		}
	}
	// 3. return to the caller
	return out
}

// URLAddressList calls NewURLAddressList using um.ID, um.DNS, and um.Endpoint.
func (um *URLMeasurement) URLAddressList() ([]*URLAddress, bool) {
	return NewURLAddressList(um.ID, um.Domain(), um.DNS, um.Endpoint)
}

const (
	// EndpointPlanningExcludeBogons excludes bogons from NewEndpointPlan's planning.
	EndpointPlanningExcludeBogons = 1 << iota

	// EndpointPlanningOnlyHTTP3 ensures we only test HTTP3.
	EndpointPlanningOnlyHTTP3

	// EndpointPlanningIncludeAll ensures that we include all the IP addresses
	// regardless on any options based restriction on the maximum number of
	// addresses per domain. This flag is used to ensure the TH receives the
	// whole list of IP addresses discovered by the client.
	EndpointPlanningIncludeAll

	// EndpointPlanningMeasureAgain ensures that we include endpoints that
	// we have already measured into the plan.
	EndpointPlanningMeasureAgain
)

// NewEndpointPlan is a convenience function that calls um.URLAddressList and passes the
// resulting list to um.NewEndpointPlanWithAddressList.
func (um *URLMeasurement) NewEndpointPlan(flags int64) ([]*EndpointPlan, bool) {
	addrs, _ := um.URLAddressList()
	return um.NewEndpointPlanWithAddressList(addrs, flags)
}

// NewEndpointPlanWithAddressList creates a new plan for measuring all the endpoints
// derived from the given address list compatibly with options constraints.
//
// Note that the returned list will include HTTP, HTTPS, and HTTP3 plans
// related to the original URL regardless of its scheme.
//
// The flags argument allows to specify flags that modify the planning
// algorithm. The EndpointPlanningExcludeBogons flag is such that we
// will not include any bogon IP address into the returned plan.
func (um *URLMeasurement) NewEndpointPlanWithAddressList(
	addrs []*URLAddress, flags int64) ([]*EndpointPlan, bool) {
	out := make([]*EndpointPlan, 0, 8)
	familyCounter := make(map[string]int64)
	for _, addr := range addrs {
		if (flags&EndpointPlanningExcludeBogons) != 0 && netxlite.IsBogon(addr.Address) {
			logcat.Scrutinizef("excluding bogon %s as requested", addr.Address)
			continue
		}

		if netxlite.IsLoopback(addr.Address) {
			logcat.Infof("[mx] excluding loopback addresses such as %s by default", addr.Address)
			continue
		}

		family := "A"
		ipv6, err := netxlite.IsIPv6(addr.Address)
		if err != nil {
			continue
		}
		if ipv6 {
			family = "AAAA"
		}
		if (flags&EndpointPlanningIncludeAll) == 0 &&
			familyCounter[family] >= um.Options.maxAddressesPerFamily() {
			logcat.Scrutinizef("too many %s addresses already, skipping %s", family, addr.Address)
			continue
		}
		counted := false

		if (flags & EndpointPlanningOnlyHTTP3) == 0 {
			if um.IsHTTP() && (!addr.AlreadyTestedHTTP() || (flags&EndpointPlanningMeasureAgain) != 0) {
				plan, err := um.newEndpointPlan(archival.NetworkTypeTCP, addr.Address, "http")
				if err != nil {
					logcat.Shrugf("[mx] cannot make plan: %s", err.Error())
					continue
				}
				out = append(out, plan)
			}

			if um.IsHTTPS() && (!addr.AlreadyTestedHTTPS() || (flags&EndpointPlanningMeasureAgain) != 0) {
				plan, err := um.newEndpointPlan(archival.NetworkTypeTCP, addr.Address, "https")
				if err != nil {
					logcat.Shrugf("[mx] cannot make plan: %s", err.Error())
					continue
				}
				out = append(out, plan)
			}

			// Even if it has already been measured, this address still counts
			// against the limit enforced by MaxAddressesPerFamily.
			counted = true
		}

		if um.IsHTTPS() && addr.SupportsHTTP3() {
			if !addr.AlreadyTestedHTTP3() || (flags&EndpointPlanningMeasureAgain) != 0 {
				plan, err := um.newEndpointPlan(archival.NetworkTypeQUIC, addr.Address, "https")
				if err != nil {
					logcat.Shrugf("[mx] cannot make plan: %s", err.Error())
					continue
				}
				out = append(out, plan)
			}

			// Even if it has already been measured, this address still counts
			// against the limit enforced by MaxAddressesPerFamily.
			counted = true
		}

		if counted {
			familyCounter[family] += 1
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
func newURLWithScheme(URL *SimpleURL, scheme string) *SimpleURL {
	return &SimpleURL{
		Scheme:   scheme,
		Host:     URL.Host,
		Path:     URL.Path,
		RawQuery: URL.RawQuery,
	}
}

// urlMakeEndpoint makes a level-4 endpoint given the address and either the URL scheme
// or the explicit port provided inside the URL.
func urlMakeEndpoint(URL *SimpleURL, address string) (string, error) {
	port, err := PortFromURL(URL)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(address, port), nil
}

// Redirects returns all the redirects seen in this URLMeasurement as a
// list of follow-up URLMeasurement instances. This function will return
// false if the returned list of follow-up measurements is empty.
func (mx *Measurer) Redirects(
	epnts []*EndpointMeasurement, opts *Options) ([]*URLMeasurement, bool) {
	uniq := make(map[string]*URLMeasurement)
	for _, epnt := range epnts {
		summary, good := epnt.RedirectSummary() // Note: this includes cookie names
		if !good {
			// We should skip this endpoint
			continue
		}
		next, good := uniq[summary]
		if !good {
			requestHeaders := mx.newHeadersForRedirect(epnt.URL)
			next = &URLMeasurement{
				ID:          mx.NextID(),
				EndpointIDs: []int64{},
				URL:         epnt.Location,
				Cookies:     epnt.NewCookies, // first set of equally-named cookies wins
				Options: opts.Chain(&Options{
					// Note: all other fields intentionally left empty. We do not
					// want to continue following HTTP and HTTPS if we've been
					// redirected to HTTPS. We want to continue doing that if the
					// location is HTTP because we want extra HTTPS info.
					DoNotInitiallyForceHTTPAndHTTPS: epnt.Location.Scheme == "https",
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
func (mx *Measurer) newHeadersForRedirect(origURL *SimpleURL) http.Header {
	// Implementation note: because the TH filters the headers it
	// accepts when importing client options, we need to avoid sending
	// fancy headers. So, let's just re-create the standard headers
	// for measuring plus the referer. (Note: today the code was failing
	// to match the TH and the probe headers because the probe did also
	// include `Host`, which TH filters out, and obviously `Host` was
	// added by the probe here before we removed the code to derive
	// follow-up requests headers from previous ones.)
	out := NewHTTPRequestHeaderForMeasuring()
	if origURL != nil { // just in case
		out.Set("Referer", origURL.String())
	}
	return out
}

// URLRedirectDeque is the type we use to manage the redirection
// queue and to follow a reasonable number of redirects.
type URLRedirectDeque struct {
	// depth counts the depth
	depth int64

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
func (mx *Measurer) NewURLRedirectDeque() *URLRedirectDeque {
	return &URLRedirectDeque{
		depth:   0,
		mem:     map[string]bool{},
		mu:      sync.Mutex{},
		options: mx.Options,
		q:       []*URLMeasurement{},
	}
}

// String returns a string representation of the deque.
func (r *URLRedirectDeque) String() string {
	defer r.mu.Unlock()
	r.mu.Lock()
	var out []string
	for _, entry := range r.q {
		out = append(out, CanonicalURLString(entry.URL))
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
func (r *URLRedirectDeque) RememberVisitedURLs(epnts []*EndpointMeasurement) {
	defer r.mu.Unlock()
	r.mu.Lock()
	for _, epnt := range epnts {
		r.mem[CanonicalURLString(epnt.URL)] = true
	}
}

// MaxDepth returns the maximum depth.
func (r *URLRedirectDeque) MaxDepth() int64 {
	return r.options.maxCrawlerDepth()
}

var (
	// ErrCrawlerDepth indicates we have reached the maximum crawler depth
	ErrCrawlerDepth = errors.New("reached maximum crawler depth")

	// ErrCrawlerEOF indicates we have measured all URLs.
	ErrCrawlerEOF = errors.New("measured all the provided URLs")
)

// PopLeft removes the first element in the redirect deque. Returns true
// if we returned an element and false when the deque is empty.
func (r *URLRedirectDeque) PopLeft() (*URLMeasurement, error) {
	defer r.mu.Unlock()
	r.mu.Lock()
	if r.depth >= r.options.maxCrawlerDepth() {
		return nil, ErrCrawlerDepth
	}
	for len(r.q) > 0 {
		um := r.q[0]
		r.q = r.q[1:]
		// TODO(bassosimone): we should also consider cookies to determine
		// whether we've already visited an URL or not.
		if repr := CanonicalURLString(um.URL); r.mem[repr] {
			logcat.Scrutinizef("skip already visited URL: %s", repr)
			continue
		}
		r.depth++ // we increment the depth when we _remove_ and measure
		return um, nil
	}
	return nil, ErrCrawlerEOF
}

// Depth returns the number or redirects we followed so far.
func (r *URLRedirectDeque) Depth() int64 {
	defer r.mu.Unlock()
	r.mu.Lock()
	return r.depth
}
