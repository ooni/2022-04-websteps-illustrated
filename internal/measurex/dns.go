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
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/archival"
	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
)

// DNSResolverInfo contains info about a DNS resolver.
type DNSResolverInfo struct {
	// Network is the resolver's network (e.g., "doh", "udp")
	Network archival.NetworkType

	// Address is the address (e.g., "1.1.1.1:53", "https://1.1.1.1/dns-query")
	Address string
}

// NewResolversHTTPS creates a list of HTTPS resolvers from a list of URLs.
func NewResolversHTTPS(urls ...string) []*DNSResolverInfo {
	out := []*DNSResolverInfo{}
	for _, url := range urls {
		out = append(out, &DNSResolverInfo{
			Network: archival.NetworkTypeDoH,
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
			Network: archival.NetworkTypeUDP,
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

	// ReverseAddress is a convenience field holding the addr for
	// which we issued a reverse lookup, which only makes sense when
	// we're actually performing a reverse lookup.
	ReverseAddress string `json:",omitempty"`

	// LookupType is the type of lookup to perform.
	LookupType archival.DNSLookupType

	// Options contains the options. If nil we'll use default values.
	Options *Options

	// Resolver is the resolver to use.
	Resolver *DNSResolverInfo
}

// Summary returns a string representing the DNS lookup's plan. Two
// plans are ~same if they have the same summary.
//
// The summary of a DNS lookup consists of these fields:
//
// - domain
// - lookupType
// - resolver network
// - resolver address
//
// If the plan is nil, we return the empty string.
func (dlp *DNSLookupPlan) Summary() string {
	if dlp == nil || dlp.Resolver == nil {
		return ""
	}
	return dnsLookupPlanOrMeasurementSummary(dlp.Domain, string(dlp.LookupType),
		string(dlp.ResolverNetwork()), dlp.ResolverAddress())
}

// dnsLookupPlanOrMeasurementSummary is the common function to
// implement the summary of a DNSLookup{Plan,Measurement}.
func dnsLookupPlanOrMeasurementSummary(
	domain, lookupType, resolverNetwork, resolverAddress string) string {
	var out []string
	out = append(out, domain)
	out = append(out, lookupType)
	out = append(out, resolverNetwork)
	out = append(out, resolverAddress)
	return strings.Join(out, " ")
}

// Equals returns wheter a plan equals another plan. Two plans are
// equal if they have the same summary.
func (dlp *DNSLookupPlan) Equals(other *DNSLookupPlan) bool {
	return dlp.Summary() == other.Summary()
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
			ReverseAddress:   "",
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
			ReverseAddress:   dlp.ReverseAddress,
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

// ResolverNetwork returns the resolver network.
func (dlp *DNSLookupPlan) ResolverNetwork() archival.NetworkType {
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
	ID int64 `json:",omitempty"`

	// URLMeasurementID is the ID of the parent URLMeasurement. We do not
	// emit this information to JSON because it is redundant, but it's still
	// handy to know it when we're processing measurements.
	URLMeasurementID int64 `json:"-"`

	// ReverseAddress is a convenience field holding the addr for
	// which we issued a reverse lookup, which only makes sense when
	// we're actually performing a reverse lookup.
	ReverseAddress string `json:",omitempty"`

	// Lookup contains the DNS lookup event. This field contains a summary
	// of the information discovered during this lookup. We recommend using
	// this structure for processing the results.
	Lookup *archival.FlatDNSLookupEvent

	// RoundTrip contains DNS round trips. This field contains one or
	// more round trips performed during the lookup. The system resolver
	// fakes out a round trip with query type ANY and all the info
	// that we could gather from calling getaddrinfo (or equivalent).
	RoundTrip []*archival.FlatDNSRoundTripEvent `json:",omitempty"`
}

// FinishedUnixNano returns the time when this measurement finished
// expressed in nanoseconds since the UNIX epoch.
func (dlm *DNSLookupMeasurement) FinishedUnixNano() int64 {
	if dlm.Lookup != nil {
		return dlm.Lookup.Finished.UnixNano()
	}
	return 0
}

// NewDNSReverseLookupPlans generates a []*DNSLookupPlan for performing
// a reverse lookup for the given list of addresses and the given resolvers.
func (um *URLMeasurement) NewDNSReverseLookupPlans(
	addrs []string, ri ...*DNSResolverInfo) []*DNSLookupPlan {
	out := []*DNSLookupPlan{}
	for _, addr := range addrs {
		if netxlite.IsBogon(addr) {
			logcat.Shrugf("cowardly refusing to reverse lookup a bogon: %s", addr)
			continue
		}
		reverseAddr, err := dns.ReverseAddr(addr)
		if err != nil {
			logcat.Bugf("cannot reverse this IP addr: %s", addr)
			continue
		}
		for _, r := range ri {
			out = append(out, &DNSLookupPlan{
				URLMeasurementID: um.ID,
				Domain:           reverseAddr,
				ReverseAddress:   addr,
				LookupType:       archival.DNSLookupTypeReverse,
				Options:          um.Options,
				Resolver:         r,
			})
		}
	}
	return out
}

// Summary returns a string representing the DNS measurement's plan. Two
// measurements are ~same if they have the same summary.
//
// The summary of a DNS lookup consists of these fields:
//
// - domain
// - lookupType
// - resolver network
// - resolver address
//
// If the measurement is nil, we return the empty string.
func (dlm *DNSLookupMeasurement) Summary() string {
	if dlm == nil {
		return ""
	}
	return dnsLookupPlanOrMeasurementSummary(dlm.Domain(), string(dlm.LookupType()),
		string(dlm.ResolverNetwork()), dlm.ResolverAddress())
}

// IsWeaklyCompatibleWith returns whether the current DNSLookupMeasurement can
// safely be compared with another DNSLookupMeasurement regardless of which
// specific DNS resolver has been used to perform the two measurements.
//
// We say that two DNSLookupMeasurements are weakly compatible if:
//
// 1. they are relative to the same domain;
//
// 2. the lookup type is compatible.
//
// The following table shows when two lookup types are weakly compatible:
//
//	+-------------+-------------+-------+--------+---------+
//	|             | getaddrinfo | https |   ns   | reverse |
//	+-------------+-------------+-------+--------+---------+
//	| getaddrinfo |     yes     |  yes  |   no   |   no    |
//	+-------------+-------------+-------+--------+---------+
//	|    https    |     yes     |  yes  |   no   |   no    |
//	+-------------+-------------+-------+--------+---------+
//	|      ns     |      no     |   no  |  yes   |   no    |
//	+-------------+-------------+-------+--------+---------+
//	|   reverse   |      no     |   no  |   no   |  yes    |
//	+-------------+-------------+-------+--------+---------+
//
// In addition, two lookup types are _always_ weakly compatible when they're the
// same, even if they are not listed in the above table.
//
// A stronger definition of compatibility is provided by IsCompatibleWith.
func (dlm *DNSLookupMeasurement) IsWeaklyCompatibleWith(other *DNSLookupMeasurement) bool {
	if dlm.Domain() != other.Domain() {
		return false // different domain means incompatible
	}
	left, right := dlm.LookupType(), other.LookupType()
	if left == right {
		return true // same lookup type means compatible
	}
	// check for cross compatibility between getaddrinfo and https
	return (left == archival.DNSLookupTypeGetaddrinfo && right == archival.DNSLookupTypeHTTPS) ||
		(left == archival.DNSLookupTypeHTTPS && right == archival.DNSLookupTypeGetaddrinfo)
}

// IsCompatibleWith returns whether the current DNSLookupMeasurement can
// safely be compared with another DNSLookupMeasurement regardless of which
// specific DNS resolver has been used to perform the two measurements.
//
// 1. they are resolving the same domain;
//
// 2. they use the same lookup type.
//
// A weaker definition of compatibility is provided by IsWeaklyCompatibleWith.
func (dlm *DNSLookupMeasurement) IsCompatibleWith(other *DNSLookupMeasurement) bool {
	return dlm.Domain() == other.Domain() && dlm.LookupType() == other.LookupType()
}

// CouldDeriveFrom returns true if this measurement could have been
// the result of the plan provided as argument. This is true when the
// summary of the measurement is equal to the plan's summary.
func (dlm *DNSLookupMeasurement) CouldDeriveFrom(p *DNSLookupPlan) bool {
	return dlm.Summary() == p.Summary()
}

// IsAnotherInstanceOf returns whether the current measurement is another instance
// of the other measurement, `o`. This is true when they have equal summary.
func (dlm *DNSLookupMeasurement) IsAnotherInstanceOf(o *DNSLookupMeasurement) bool {
	return dlm.Summary() == o.Summary()
}

// UsingResolverIPv6 returns whether this DNS lookups used an IPv6 resolver.
func (dlm *DNSLookupMeasurement) UsingResolverIPv6() (usingIPv6 bool) {
	if dlm.Lookup != nil {
		switch v := dlm.Lookup.ResolverNetwork; v {
		case "tcp", "udp", "dot":
			usingIPv6 = isEndpointIPv6(dlm.ResolverAddress())
		default:
			logcat.Bugf("UsingResolverIPv6: case %s: not implemented", v)
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
	return fmt.Sprintf("#%d %s lookup for %s using %s", dlm.ID, dlm.Lookup.LookupType,
		dlm.Domain(), dlm.ResolverURL())
}

// Addresses returns the list of addresses we discovered during the lookup.
func (dlm *DNSLookupMeasurement) Addresses() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.Addresses
	}
	return nil
}

// PTRs returns the PTRs we discovered during the lookup.
func (dlm *DNSLookupMeasurement) PTRs() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.PTRs
	}
	return nil
}

// CNAME returns the CNAME we discovered during the lookup.
func (dlm *DNSLookupMeasurement) CNAME() string {
	if dlm.Lookup != nil {
		return dlm.Lookup.CNAME
	}
	return ""
}

// ALPNs returns the list of ALPNs we discovered during the lookup.
func (dlm *DNSLookupMeasurement) ALPNs() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.ALPNs
	}
	return nil
}

// NS returns the list of NS we discovered during the lookup.
func (dlm *DNSLookupMeasurement) NS() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.NS
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
	switch v := dlm.ResolverNetwork(); v {
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
	case "dnscache":
		return "dnscache:///"
	default:
		logcat.Bugf("ResolverURL not implemented for: %s, %s", v, dlm.ResolverAddress())
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
	case archival.NetworkTypeSystem:
		switch t.LookupType {
		case archival.DNSLookupTypeGetaddrinfo:
			output <- mx.lookupHostSystem(ctx, t)
		default:
			logcat.Bugf("asked the system resolver for %s lookup type", t.LookupType)
		}
	case archival.NetworkTypeUDP:
		switch t.LookupType {
		case archival.DNSLookupTypeGetaddrinfo:
			output <- mx.lookupHostUDP(ctx, t)
		case archival.DNSLookupTypeHTTPS:
			output <- mx.lookupHTTPSSvcUDP(ctx, t)
		case archival.DNSLookupTypeNS:
			output <- mx.lookupNSUDP(ctx, t)
		default:
			logcat.Bugf("asked the UDP resolver for %s lookup type", t.LookupType)
		}
	case archival.NetworkTypeDoH, archival.NetworkTypeDoH3:
		switch t.LookupType {
		case archival.DNSLookupTypeGetaddrinfo:
			output <- mx.lookupHostDoH(ctx, t)
		case archival.DNSLookupTypeHTTPS:
			output <- mx.lookupHTTPSSvcDoH(ctx, t)
		case archival.DNSLookupTypeNS:
			output <- mx.lookupNSDoH(ctx, t)
		case archival.DNSLookupTypeReverse:
			output <- mx.lookupReverseDoH(ctx, t)
		default:
			logcat.Bugf("asked the HTTPS resolver for %s lookup type", t.LookupType)
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
	case archival.NetworkTypeDoH3:
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

// lookupReverseDoH performs a reverse lookup using a DoH resolver.
func (mx *Measurer) lookupReverseDoH(
	ctx context.Context, t *DNSLookupPlan) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.ResolverNetwork()), t.ResolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupReverse(ctx, t.Domain, r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

// doLookupHost is the worker function to perform an A and AAAA lookup.
func (mx *Measurer) doLookupHost(ctx context.Context, domain string,
	r model.Resolver, t *DNSLookupPlan, id int64) ([]string, error) {
	ol := NewOperationLogger("[#%d] LookupHost %s with %s resolver %s",
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
	ol := NewOperationLogger("[#%d] LookupHTTPSvc %s with %s resolver %s",
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
	ol := NewOperationLogger("[#%d] LookupNS %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ns, err := r.LookupNS(ctx, domain)
	ol.Stop(err)
	return ns, err
}

// doLookupReverse is the worker function to perform a reverse lookup.
func (mx *Measurer) doLookupReverse(ctx context.Context, domain string,
	r model.Resolver, t *DNSLookupPlan, id int64) ([]string, error) {
	ol := NewOperationLogger("[#%d] LookupReverse %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ptrs, err := r.LookupPTR(ctx, domain)
	ol.Stop(err)
	return ptrs, err
}

// newDNSLookupMeasurement is the internal factory for creating a DNSLookupMeasurement.
func (mx *Measurer) newDNSLookupMeasurement(id int64,
	t *DNSLookupPlan, trace *archival.Trace) *DNSLookupMeasurement {
	out := &DNSLookupMeasurement{
		ID:               id,
		URLMeasurementID: t.URLMeasurementID,
		ReverseAddress:   t.ReverseAddress,
		Lookup:           nil,
		RoundTrip:        nil,
	}
	if len(trace.DNSLookup) != 1 {
		logcat.Bugf("expected a single DNSLookup entry: %+v", trace.DNSLookup)
	}
	if len(trace.DNSLookup) == 1 {
		out.Lookup = trace.DNSLookup[0]
	}
	out.RoundTrip = trace.DNSRoundTrip
	return out
}

// NewFakeHTTPSSvcDNSLookupMeasurement creates a fake DNSLookupMeasurement
// from IP addresses obtained from an external source.
//
// This factory is the best solution to fake a DNS lookup that can be
// compared with other DNS lookups. Because the returned lookup may also
// include ALPN information, we're faking an HTTPSSvc lookup result.
func NewFakeHTTPSSvcDNSLookupMeasurement(mx AbstractMeasurer,
	resolverNetwork archival.NetworkType, resolverAddress string,
	domain string, alpns []string, addresses []string) *DNSLookupMeasurement {
	return newFakeHTTPSSvcDNSLookupMeasurement(
		0, mx, resolverNetwork, resolverAddress, domain, alpns, addresses)
}

// newFakeHTTPSvcDNSLookupMeasurement is the internal version of NewHTTPSSvcDNSLookupMeasurement
// that also allows us to configure a specific URL measurement ID.
func newFakeHTTPSSvcDNSLookupMeasurement(urlMeasurementID int64, mx AbstractMeasurer,
	resolverNetwork archival.NetworkType, resolverAddress string,
	domain string, alpns []string, addresses []string) *DNSLookupMeasurement {
	return &DNSLookupMeasurement{
		ID:               mx.NextID(),
		URLMeasurementID: urlMeasurementID,
		ReverseAddress:   "",
		Lookup: archival.NewFakeFlatDNSLookupEvent(
			resolverNetwork, resolverAddress, archival.DNSLookupTypeHTTPS,
			domain, alpns, addresses,
		),
		RoundTrip: []*archival.FlatDNSRoundTripEvent{},
	}
}
