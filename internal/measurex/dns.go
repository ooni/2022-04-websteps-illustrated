package measurex

//
// DNS
//
// This file contains code to perform DNS measurements.
//
// Note that this file is not part of probe-cli.
//

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// DNSResolverNetwork identifies the network of a resolver.
type DNSResolverNetwork string

var (
	// DNSResolverSystem is the system resolver (i.e., getaddrinfo)
	DNSResolverSystem = DNSResolverNetwork("system")

	// DNSResolverUDP is a resolver using DNS-over-UDP
	DNSResolverUDP = DNSResolverNetwork("udp")

	// DNSResolverDoH is a resolver using DNS-over-HTTPS
	DNSResolverDoH = DNSResolverNetwork("doh")

	// DNSResolverDoH3 is a resolver using DNS-over-HTTP3
	DNSResolverDoH3 = DNSResolverNetwork("doh3")
)

// DNSResolverInfo contains info about a DNS resolver.
type DNSResolverInfo struct {
	// Network is the resolver's network (e.g., "doh", "udp")
	Network DNSResolverNetwork

	// Address is the address (e.g., "1.1.1.1:53", "https://1.1.1.1/dns-query")
	Address string
}

// NewResolversHTTPS creates a list of HTTPS resolvers from a list of URLs.
func NewResolversHTTPS(urls ...string) []*DNSResolverInfo {
	out := []*DNSResolverInfo{}
	for _, url := range urls {
		out = append(out, &DNSResolverInfo{
			Network: DNSResolverDoH,
			Address: url,
		})
	}
	return out
}

// Equals returns whether a DNSResolverInfo equals another one.
func (dri *DNSResolverInfo) Equals(other *DNSResolverInfo) bool {
	return (dri == nil && other == nil) || (dri != nil && other != nil &&
		dri.Network == other.Network && dri.Address == other.Address)
}

// Clone returns a clone of this resolver info.
func (dri *DNSResolverInfo) Clone() (out *DNSResolverInfo) {
	if dri != nil {
		out = &DNSResolverInfo{
			Network: dri.Network,
			Address: dri.Address,
		}
	}
	return
}

// NewResolversUDP creates a list of UDP resolvers from a list of endpoints.
func NewResolversUDP(endpoints ...string) []*DNSResolverInfo {
	out := []*DNSResolverInfo{}
	for _, epnt := range endpoints {
		out = append(out, &DNSResolverInfo{
			Network: DNSResolverUDP,
			Address: epnt,
		})
	}
	return out
}

// DNSLookupPlan is a plan for performing a DNS lookup.
type DNSLookupPlan struct {
	// URLMeasurementID is the ID of the original URLMeasurement.
	URLMeasurementID int64 `json:",omitempty"`

	// Domain is the domain to measure.
	Domain string

	// LookupType is the type of lookup to perform.
	LookupType archival.DNSLookupType

	// Options contains the options. If nil we'll use default values.
	Options *Options

	// Resolver is the resolver to use.
	Resolver *DNSResolverInfo
}

// Equals returns wheter a plan equals another plan.
func (dlp *DNSLookupPlan) Equals(other *DNSLookupPlan) bool {
	return (dlp == nil && other == nil) || (dlp != nil && other != nil &&
		dlp.Domain == other.Domain && dlp.LookupType == other.LookupType &&
		dlp.Resolver.Equals(other.Resolver))
}

// NewDNSLookupPlans creates a plan for measuring the given domain with the given
// options using the given list of resolvers. By default, we perform a getaddrinfo
// like lookup (i.e., A and AAAA). Use flags to add additional lookup types. For
// example, you can add a NS lookup using DNSLookupTypeNS.
func NewDNSLookupPlans(domain string, options *Options,
	flags int64, ri ...*DNSResolverInfo) []*DNSLookupPlan {
	return newDNSLookupPlans(0, domain, options, flags, ri...)
}

// newDNSLookupPlans is NewDNSLookupPlans with explicit urlMeasurementID. Use
// for constructing plans associated with an URLMeasurement.
func newDNSLookupPlans(urlMeasurementID int64, domain string,
	options *Options, flags int64, ri ...*DNSResolverInfo) []*DNSLookupPlan {
	out := []*DNSLookupPlan{}
	for _, r := range ri {
		basePlan := &DNSLookupPlan{
			URLMeasurementID: urlMeasurementID,
			Domain:           domain,
			LookupType:       archival.DNSLookupTypeGetaddrinfo,
			Options:          options,
			Resolver:         r,
		}
		out = append(out, basePlan)
		if (flags&DNSLookupFlagHTTPS) != 0 && r.Network != "system" {
			out = append(out, basePlan.CloneWithLookupType(archival.DNSLookupTypeHTTPS))
		}
		if (flags&DNSLookupFlagNS) != 0 && r.Network != "system" {
			out = append(out, basePlan.CloneWithLookupType(archival.DNSLookupTypeNS))
		}
	}
	return out
}

// Clone creates a DNSLookupPlan deep copy.
func (dlp *DNSLookupPlan) Clone() (out *DNSLookupPlan) {
	if dlp != nil {
		out = &DNSLookupPlan{
			URLMeasurementID: dlp.URLMeasurementID,
			Domain:           dlp.Domain,
			LookupType:       dlp.LookupType,
			Options:          dlp.Options.Flatten(),
			Resolver:         dlp.Resolver.Clone(),
		}
	}
	return
}

// CloneWithLookupType clones the original plan, configures the
// required lookup type, and returns the modified clone.
func (dlp *DNSLookupPlan) CloneWithLookupType(lt archival.DNSLookupType) (out *DNSLookupPlan) {
	if dlp != nil {
		out = dlp.Clone()
		out.LookupType = lt
	}
	return
}

const (
	// DNSLookupFlagNS modifies the DNSLookupPlan to request resolving
	// the target domain's nameservers using NS.
	DNSLookupFlagNS = 1 << iota

	// DNSLookupFlagHTTPS modifies the DNSLookupPlan to request resolving
	// the target domain using HTTPSSvc.
	DNSLookupFlagHTTPS
)

// DNSLookupMeasurement is a DNS lookup measurement.
type DNSLookupMeasurement struct {
	// ID is the unique ID of this measurement.
	ID int64

	// URLMeasurementID is the ID of the parent URLMeasurement. We do not
	// emit this information to JSON because it is redundant, but it's still
	// handy to know it when we're processing measurements.
	URLMeasurementID int64 `json:"-"`

	// Lookup contains the DNS lookup event. This field contains a summary
	// of the information discovered during this lookup. We recommend using
	// this structure for processing the results.
	Lookup *archival.FlatDNSLookupEvent

	// RoundTrip contains DNS round trips. This field contains one or
	// more round trips performed during the lookup. The system resolver
	// fakes out a round trip with query type ANY and all the info
	// that we could gather from calling getaddrinfo (or equivalent).
	RoundTrip []*archival.FlatDNSRoundTripEvent
}

// UsingResolverIPv6 returns whether this DNS lookups used an IPv6 resolver.
func (dlm *DNSLookupMeasurement) UsingResolverIPv6() (usingIPv6 bool) {
	if dlm.Lookup != nil {
		switch dlm.Lookup.ResolverNetwork {
		case "tcp", "udp", "dot":
			usingIPv6 = isEndpointIPv6(dlm.ResolverAddress())
		case "doh":
			// TODO(bassosimone): implement this case
			log.Printf("[BUG] UsingResolverIPv6: doh case is not implemented")
		default:
			// nothing
		}
	}
	return
}

// Runtime returns the time elapsed waiting for the lookup to complete.
func (dlm *DNSLookupMeasurement) Runtime() (out time.Duration) {
	if dlm.Lookup != nil {
		out = dlm.Lookup.Finished.Sub(dlm.Lookup.Started)
	}
	return
}

// Describe returns a compact human-readable description of this measurement.
func (dlm *DNSLookupMeasurement) Describe() string {
	return fmt.Sprintf("[#%d] DNS lookup #%d for %s using %s",
		dlm.URLMeasurementID, dlm.ID, dlm.Domain(), dlm.ResolverURL())
}

// Addresses returns the list of addresses we discovered during the lookup.
func (dlm *DNSLookupMeasurement) Addresses() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.Addresses
	}
	return nil
}

// ALPNs returns the list of ALPNs we discovered during the lookup.
func (dlm *DNSLookupMeasurement) ALPNs() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.ALPNs
	}
	return nil
}

// Domain returns the domain for which we issued a DNS lookup.
func (dlm *DNSLookupMeasurement) Domain() string {
	if dlm.Lookup != nil {
		return dlm.Lookup.Domain
	}
	return ""
}

// Failure returns the failure that occurred.
func (dlm *DNSLookupMeasurement) Failure() archival.FlatFailure {
	if dlm.Lookup != nil {
		return dlm.Lookup.Failure
	}
	return ""
}

// LookupType returns the lookup type (e.g., getaddrinfo, NS).
func (dlm *DNSLookupMeasurement) LookupType() archival.DNSLookupType {
	if dlm.Lookup != nil {
		return dlm.Lookup.LookupType
	}
	return ""
}

// ResolverAddress returns the resolver address (e.g., 8.8.8.8:53).
func (dlm *DNSLookupMeasurement) ResolverAddress() string {
	if dlm.Lookup != nil {
		return dlm.Lookup.ResolverAddress
	}
	return ""
}

// ResolverNetwork returns the resolver network (e.g., udp, system).
func (dlm *DNSLookupMeasurement) ResolverNetwork() archival.NetworkType {
	if dlm.Lookup != nil {
		return dlm.Lookup.ResolverNetwork
	}
	return ""
}

// ResolverURL returns a URL containing the resolver's network and address. For
// DoH resolvers, we just return the URL. For all the other resolvers, we use the
// network as the scheme and the address as the URL host.
func (dlm *DNSLookupMeasurement) ResolverURL() string {
	switch dlm.ResolverNetwork() {
	case archival.NetworkTypeUDP:
		return fmt.Sprintf("udp://%s", dlm.ResolverAddress())
	case archival.NetworkTypeTCP:
		return fmt.Sprintf("tcp://%s", dlm.ResolverAddress())
	case archival.NetworkTypeDoT:
		return fmt.Sprintf("dot://%s", dlm.ResolverAddress())
	case archival.NetworkTypeDoH:
		return dlm.ResolverAddress()
	case "system":
		return "system:///"
	default:
		return ""
	}
}

// SupportsHTTP3 returns whether this DNSLookupMeasurement includes the
// "h3" ALPN in the list of ALPNs for this domain.
func (dlm *DNSLookupMeasurement) SupportsHTTP3() bool {
	for _, alpn := range dlm.ALPNs() {
		if alpn == "h3" {
			return true
		}
	}
	return false
}

// ResolverNetwork returns the resolver network.
func (dlp *DNSLookupPlan) ResolverNetwork() DNSResolverNetwork {
	if dlp.Resolver != nil {
		return dlp.Resolver.Network
	}
	return ""
}

// ResolverAddress returns the resolver address.
func (dlp *DNSLookupPlan) ResolverAddress() string {
	if dlp.Resolver != nil {
		return dlp.Resolver.Address
	}
	return ""
}

// DNSLookups performs DNS lookups in parallel.
//
// This function returns a channel where to read/ measurements
// from. The channel is closed when done.
func (mx *Measurer) DNSLookups(ctx context.Context,
	dnsLookups ...*DNSLookupPlan) <-chan *DNSLookupMeasurement {
	var (
		plans  = make(chan *DNSLookupPlan)
		output = make(chan *DNSLookupMeasurement)
		done   = make(chan interface{})
	)
	go func() {
		defer close(plans)
		for _, plan := range dnsLookups {
			plans <- plan
		}
	}()
	parallelism := mx.Options.dnsParallelism()
	for i := int64(0); i < parallelism; i++ {
		go func() {
			for t := range plans {
				mx.dnsLookup(ctx, t, output)
			}
			done <- true
		}()
	}
	go func() {
		for i := int64(0); i < parallelism; i++ {
			<-done // wait for background goroutine to join
		}
		close(output) // synchronize with caller
	}()
	return output
}

// dnsLookup performs a dnsLookup in the background.
func (mx *Measurer) dnsLookup(ctx context.Context,
	t *DNSLookupPlan, output chan<- *DNSLookupMeasurement) {
	switch t.ResolverNetwork() {
	case DNSResolverSystem:
		switch t.LookupType {
		case archival.DNSLookupTypeGetaddrinfo:
			output <- mx.lookupHostSystem(ctx, t)
		default:
			log.Printf("[BUG] asked the system resolver for %s lookup type", t.LookupType)
		}
	case DNSResolverUDP:
		switch t.LookupType {
		case archival.DNSLookupTypeGetaddrinfo:
			output <- mx.lookupHostUDP(ctx, t)
		case archival.DNSLookupTypeHTTPS:
			output <- mx.lookupHTTPSSvcUDP(ctx, t)
		case archival.DNSLookupTypeNS:
			output <- mx.lookupNSUDP(ctx, t)
		}
	case DNSResolverDoH, DNSResolverDoH3:
		switch t.LookupType {
		case archival.DNSLookupTypeGetaddrinfo:
			output <- mx.lookupHostDoH(ctx, t)
		case archival.DNSLookupTypeHTTPS:
			output <- mx.lookupHTTPSSvcDoH(ctx, t)
		case archival.DNSLookupTypeNS:
			output <- mx.lookupNSDoH(ctx, t)
		}
	}
}

// lookupHostSystem performs a getaddrinfo lookup using the system resolver.
func (mx *Measurer) lookupHostSystem(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverSystem(saver)
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupHost(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// lookupHostUDP queries for A and AAAA using an UDP resolver.
func (mx *Measurer) lookupHostUDP(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.ResolverAddress())
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupHost(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// lookupHostDoH queries for A and AAAA using a DoH resolver.
func (mx *Measurer) lookupHostDoH(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.ResolverNetwork()), t.ResolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupHost(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// httpClientForDNSLookupTarget returns an HTTP or an HTTP3 client depending
// on whether the resolver network implies using HTTP3.
func (mx *Measurer) httpClientForDNSLookupTarget(t *DNSLookupPlan) model.HTTPClient {
	switch t.ResolverNetwork() {
	case DNSResolverDoH3:
		return mx.HTTP3ClientForDoH
	default:
		return mx.HTTPClientForDoH
	}
}

// lookupHTTPSSvcUDP performs an HTTPSSvc lookup using an UDP resolver.
func (mx *Measurer) lookupHTTPSSvcUDP(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.ResolverAddress())
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupHTTPSSvc(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// lookupHTTPSvcDoH performs an HTTPSSvc lookup using a DoH resolver.
func (mx *Measurer) lookupHTTPSSvcDoH(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.ResolverNetwork()), t.ResolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupHTTPSSvc(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// lookupNSUDP uses an UDP resolver to send a NS query.
func (mx *Measurer) lookupNSUDP(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.ResolverAddress())
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupNS(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// lookupNSDoH uses a DoH resolver to send a DoH query.
func (mx *Measurer) lookupNSDoH(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.ResolverNetwork()), t.ResolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupNS(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// doLookupHost is the worker function to perform an A and AAAA lookup.
func (mx *Measurer) doLookupHost(ctx context.Context, domain string,
	r model.Resolver, t *DNSLookupPlan, id int64) ([]string, error) {
	ol := NewOperationLogger(mx.Logger, "[#%d] LookupHost %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return addrs, err
}

// doLookupHTTPSSvc is the worker function to perform an HTTPSSvc lookup.
func (mx *Measurer) doLookupHTTPSSvc(ctx context.Context, domain string,
	r model.Resolver, t *DNSLookupPlan, id int64) (*model.HTTPSSvc, error) {
	ol := NewOperationLogger(mx.Logger, "[#%d] LookupHTTPSvc %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	https, err := r.LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return https, err
}

// doLookupNS is the worker function to perform a NS lookup.
func (mx *Measurer) doLookupNS(ctx context.Context, domain string,
	r model.Resolver, t *DNSLookupPlan, id int64) ([]*net.NS, error) {
	ol := NewOperationLogger(mx.Logger, "[#%d] LookupNS %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ns, err := r.LookupNS(ctx, domain)
	ol.Stop(err)
	return ns, err
}

// newDNSLookupMeasurement is the internal factory for creating a DNSLookupMeasurement.
func (mx *Measurer) newDNSLookupMeasurement(id int64,
	t *DNSLookupPlan, trace *archival.Trace) *DNSLookupMeasurement {
	out := &DNSLookupMeasurement{
		ID:               id,
		URLMeasurementID: t.URLMeasurementID,
		Lookup:           nil,
		RoundTrip:        nil,
	}
	if len(trace.DNSLookup) != 1 {
		log.Printf("[BUG] expected a single DNSLookup entry: %+v", trace.DNSLookup)
	}
	if len(trace.DNSLookup) == 1 {
		out.Lookup = trace.DNSLookup[0]
	}
	out.RoundTrip = trace.DNSRoundTrip
	return out
}
