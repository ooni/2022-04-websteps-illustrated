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
	"sync"
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

// DNSLookupPlan is a plan for performing a DNS lookup.
type DNSLookupPlan struct {
	// URLMeasurementID is the ID of the original URLMeasurement.
	URLMeasurementID int64

	// URL is the URL to resolve.
	URL *SimpleURL

	// Options contains the options. If nil we'll use default values.
	Options *Options

	// Resolvers describes the resolvers to use.
	Resolvers []*DNSResolverInfo

	// Flags contains optional flags to perform extra queries.
	Flags int64
}

// Clone creates a DNSLookupPlan deep copy.
func (dlp *DNSLookupPlan) Clone() *DNSLookupPlan {
	out := &DNSLookupPlan{
		URLMeasurementID: dlp.URLMeasurementID,
		URL:              dlp.URL.Clone(),
		Options:          dlp.Options.Flatten(),
		Resolvers:        []*DNSResolverInfo{},
		Flags:            dlp.Flags,
	}
	for _, ri := range dlp.Resolvers {
		out.Resolvers = append(out.Resolvers, &DNSResolverInfo{
			Network: ri.Network,
			Address: ri.Address,
		})
	}
	return out
}

// Domain returns the domain used by the plan.
func (dlp *DNSLookupPlan) Domain() string {
	if dlp.URL != nil {
		return dlp.URL.Hostname()
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
	ID int64

	// URLMeasurementID is the ID of the parent URLMeasurement.
	URLMeasurementID int64 `json:"-"`

	// Lookup contains the DNS lookup event.
	Lookup *archival.FlatDNSLookupEvent

	// RoundTrip contains DNS round trips.
	RoundTrip []*archival.FlatDNSRoundTripEvent `json:",omitempty"`
}

// UsingResolverIPv6 returns true whether this specific DNS lookup
// has used an IPv6 resolver, false otherwise.
func (dlm *DNSLookupMeasurement) UsingResolverIPv6() (usingIPv6 bool) {
	if dlm.Lookup != nil {
		switch dlm.Lookup.ResolverNetwork {
		case "tcp", "udp", "dot":
			usingIPv6 = isEndpointIPv6(dlm.ResolverAddress())
		case "doh":
			// TODO(bassosimone): implement this case
			log.Printf("UsingResolverIPv6: doh case is not implemented")
		default:
			// nothing
		}
	}
	return
}

// Runtime is the runtime of this query.
func (dlm *DNSLookupMeasurement) Runtime() (out time.Duration) {
	if dlm.Lookup != nil {
		out = dlm.Lookup.Finished.Sub(dlm.Lookup.Started)
	}
	return
}

// Describe describes this measurement.
func (dlm *DNSLookupMeasurement) Describe() string {
	return fmt.Sprintf("[#%d] DNS lookup #%d for %s using %s",
		dlm.URLMeasurementID, dlm.ID, dlm.Domain(), dlm.ResolverURL())
}

// Addresses returns the list of addresses we looked up. If we didn't lookup
// any address, we just return a nil list.
func (dlm *DNSLookupMeasurement) Addresses() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.Addresses
	}
	return nil
}

// ALPNs returns the list of ALPNs we looked up. If we didn't lookup
// any ALPN, we just return a nil list.
func (dlm *DNSLookupMeasurement) ALPNs() []string {
	if dlm.Lookup != nil {
		return dlm.Lookup.ALPNs
	}
	return nil
}

// Domain returns the domain we looked up or an empty string.
func (dlm *DNSLookupMeasurement) Domain() string {
	if dlm.Lookup != nil {
		return dlm.Lookup.Domain
	}
	return ""
}

// Failure returns the flat failure that occurred.
func (dlm *DNSLookupMeasurement) Failure() archival.FlatFailure {
	if dlm.Lookup != nil {
		return dlm.Lookup.Failure
	}
	return ""
}

// LookupType returns the lookup type or empty string.
func (dlm *DNSLookupMeasurement) LookupType() archival.DNSLookupType {
	if dlm.Lookup != nil {
		return dlm.Lookup.LookupType
	}
	return ""
}

// ResolverAddress returns the resolver address.
func (dlm *DNSLookupMeasurement) ResolverAddress() string {
	if dlm.Lookup != nil {
		return dlm.Lookup.ResolverAddress
	}
	return ""
}

// ResolverNetwork returns the resolver network.
func (dlm *DNSLookupMeasurement) ResolverNetwork() archival.NetworkType {
	if dlm.Lookup != nil {
		return dlm.Lookup.ResolverNetwork
	}
	return ""
}

// ResolverURL returns the URL that identifies the resolver network and address.
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

// dnsLookupTarget uniquely identifies a given DNS lookup.
type dnsLookupTarget struct {
	// info uniquely identifies the resolver.
	info *DNSResolverInfo

	// plan is the overall plan.
	plan *DNSLookupPlan
}

// targetDomain returns the domain we want to query.
func (p *dnsLookupTarget) targetDomain() string {
	return p.plan.URL.Hostname()
}

// resolverNetwork returns the resolver network.
func (p *dnsLookupTarget) resolverNetwork() DNSResolverNetwork {
	return p.info.Network
}

// resolverAddress returns the resolver address.
func (p *dnsLookupTarget) resolverAddress() string {
	return p.info.Address
}

// DNSLookups performs DNS lookups in parallel.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
//
// This function returns to the caller a channel where to read
// measurements from. The channel is closed when done.
func (mx *Measurer) DNSLookups(ctx context.Context, dnsLookups ...*DNSLookupPlan) <-chan *DNSLookupMeasurement {
	var (
		targets = make(chan *dnsLookupTarget)
		output  = make(chan *DNSLookupMeasurement)
		done    = make(chan interface{})
	)
	go func() {
		defer close(targets)
		for _, lookup := range dnsLookups {
			for _, r := range lookup.Resolvers {
				targets <- &dnsLookupTarget{
					info: r,
					plan: lookup,
				}
			}
		}
	}()
	parallelism := mx.Options.dnsParallelism()
	for i := int64(0); i < parallelism; i++ {
		go func() {
			for pair := range targets {
				mx.dnsLookup(ctx, pair, output)
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

func (mx *Measurer) dnsLookup(ctx context.Context,
	t *dnsLookupTarget, output chan<- *DNSLookupMeasurement) {
	wg := &sync.WaitGroup{}
	switch t.resolverNetwork() {
	case DNSResolverSystem:
		output <- mx.lookupHostSystem(ctx, t)
	case DNSResolverUDP:
		wg.Add(1)
		go func() {
			output <- mx.lookupHostUDP(ctx, t)
			wg.Done()
		}()
		if (t.plan.Flags & DNSLookupFlagHTTPS) != 0 {
			wg.Add(1)
			go func() {
				output <- mx.lookupHTTPSSvcUDP(ctx, t)
				wg.Done()
			}()
		}
		if (t.plan.Flags & DNSLookupFlagNS) != 0 {
			wg.Add(1)
			go func() {
				output <- mx.lookupNSUDP(ctx, t)
				wg.Done()
			}()
		}
	case DNSResolverDoH, DNSResolverDoH3:
		wg.Add(1)
		go func() {
			output <- mx.lookupHostDoH(ctx, t)
			wg.Done()
		}()
		if (t.plan.Flags & DNSLookupFlagHTTPS) != 0 {
			wg.Add(1)
			go func() {
				output <- mx.lookupHTTPSSvcDoH(ctx, t)
				wg.Done()
			}()
		}
		if (t.plan.Flags & DNSLookupFlagNS) != 0 {
			wg.Add(1)
			go func() {
				output <- mx.lookupNSDoH(ctx, t)
				wg.Done()
			}()
		}
	}
	wg.Wait()
}

func (mx *Measurer) lookupHostSystem(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverSystem(saver)
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupHost(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHostUDP(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.resolverAddress())
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupHost(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHostDoH(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.resolverNetwork()), t.resolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupHost(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) httpClientForDNSLookupTarget(t *dnsLookupTarget) model.HTTPClient {
	switch t.resolverNetwork() {
	case DNSResolverDoH3:
		return mx.HTTP3ClientForDoH
	default:
		return mx.HTTPClientForDoH
	}
}

func (mx *Measurer) lookupHTTPSSvcUDP(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.resolverAddress())
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupHTTPSSvc(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHTTPSSvcDoH(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.resolverNetwork()), t.resolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupHTTPSSvc(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupNSUDP(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.resolverAddress())
	defer r.CloseIdleConnections()
	id := mx.NextID()
	_, _ = mx.doLookupNS(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupNSDoH(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	hc := mx.httpClientForDNSLookupTarget(t)
	r := mx.Library.NewResolverDoH(
		saver, hc, string(t.resolverNetwork()), t.resolverAddress())
	// Note: no close idle connections because actually we'd like to keep
	// open connections with the server.
	id := mx.NextID()
	_, _ = mx.doLookupNS(ctx, t.targetDomain(), r, t, id)
	return mx.newDNSLookupMeasurement(id, t, saver.MoveOutTrace())
}

func (mx *Measurer) doLookupHost(ctx context.Context, domain string,
	r model.Resolver, t *dnsLookupTarget, id int64) ([]string, error) {
	ol := NewOperationLogger(mx.Logger, "[#%d] LookupHost %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.plan.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return addrs, err
}

func (mx *Measurer) doLookupHTTPSSvc(ctx context.Context, domain string,
	r model.Resolver, t *dnsLookupTarget, id int64) (*model.HTTPSSvc, error) {
	ol := NewOperationLogger(mx.Logger, "[#%d] LookupHTTPSvc %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.plan.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	https, err := r.LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return https, err
}

func (mx *Measurer) doLookupNS(ctx context.Context, domain string,
	r model.Resolver, t *dnsLookupTarget, id int64) ([]*net.NS, error) {
	ol := NewOperationLogger(mx.Logger, "[#%d] LookupNS %s with %s resolver %s",
		id, domain, r.Network(), r.Address())
	timeout := t.plan.Options.dnsLookupTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ns, err := r.LookupNS(ctx, domain)
	ol.Stop(err)
	return ns, err
}

func (mx *Measurer) newDNSLookupMeasurement(id int64,
	t *dnsLookupTarget, trace *archival.Trace) *DNSLookupMeasurement {
	out := &DNSLookupMeasurement{
		ID:               id,
		URLMeasurementID: t.plan.URLMeasurementID,
	}
	if len(trace.DNSLookup) > 1 {
		log.Printf("warning: more than one DNSLookup entry: %+v", trace.DNSLookup)
	}
	if len(trace.DNSLookup) == 1 {
		out.Lookup = trace.DNSLookup[0]
	}
	out.RoundTrip = trace.DNSRoundTrip
	return out
}
