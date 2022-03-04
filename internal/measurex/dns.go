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
	"log"
	"net/url"
	"sync"

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

	// DNSResolverForeign is a resolver that is not managed by
	// this package. We can wrap it, but we don't be able to
	// observe any event but Lookup{Host,HTTPSvc}
	DNSResolverForeign = DNSResolverNetwork("foreign")
)

// DNSResolverInfo contains info about a DNS resolver.
type DNSResolverInfo struct {
	// Network is the resolver's network (e.g., "doh", "udp")
	Network DNSResolverNetwork

	// Address is the address (e.g., "1.1.1.1:53", "https://1.1.1.1/dns-query")
	Address string

	// ForeignResolver is only used when Network's
	// value equals the ResolverForeign constant.
	//
	// This resolver MUST be already wrapped using
	// netxlite to have error wrapping, etc.
	ForeignResolver model.Resolver
}

// DNSLookupPlan is a plan for performing a DNS lookup.
type DNSLookupPlan struct {
	// URLMeasurementID is the ID of the original URLMeasurement.
	URLMeasurementID int64

	// URL is the URL to resolve.
	URL *url.URL

	// Resolvers describes the resolvers to use.
	Resolvers []*DNSResolverInfo
}

// DNSLookupMeasurement is a DNS lookup measurement.
type DNSLookupMeasurement struct {
	// Domain is the domain this measurement refers to.
	Domain string

	// URLMeasurementID is the ID of the parent URLMeasurement.
	URLMeasurementID int64

	// ID is the unique ID of this measurement.
	ID int64

	// Lookup contains the DNS lookup event.
	Lookup *archival.FlatDNSLookupEvent

	// RoundTrip contains DNS round trips.
	RoundTrip []*archival.FlatDNSRoundTripEvent
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

// SupportsHTTP3 returns whether this DNSLookupMeasurement includes the "h3"
// ALPN in the list of ALPNs for this domain.
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

// isHTTPS returns whether the targer URL scheme is HTTPS.
func (p *dnsLookupTarget) isHTTPS() bool {
	return p.plan.URL.Scheme == "https"
}

// resolverNetwork returns the resolver network.
func (p *dnsLookupTarget) resolverNetwork() DNSResolverNetwork {
	return p.info.Network
}

// resolverAddress returns the resolver address.
func (p *dnsLookupTarget) resolverAddress() string {
	return p.info.Address
}

// foreignResolver returns the foreign resolver.
func (p *dnsLookupTarget) foreignResolver() model.Resolver {
	return p.info.ForeignResolver
}

// DNSLookups performs DNS lookups in parallel.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
//
// This function returns to the caller a channel where to read
// measurements from. The channel is closed when done.
func (mx *Measurer) DNSLookups(ctx context.Context, parallelism int, dnsLookups ...*DNSLookupPlan) <-chan *DNSLookupMeasurement {
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
	if parallelism <= 0 {
		parallelism = 4
	}
	for i := 0; i < parallelism; i++ {
		go func() {
			for pair := range targets {
				mx.dnsLookup(ctx, pair, output)
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
		if t.isHTTPS() {
			wg.Add(1)
			go func() {
				output <- mx.lookupHTTPSSvcUDP(ctx, t)
				wg.Done()
			}()
		}

	case DNSResolverForeign:
		wg.Add(1)
		go func() {
			output <- mx.lookupHostForeign(ctx, t)
			wg.Done()
		}()
		if t.isHTTPS() {
			wg.Add(1)
			go func() {
				output <- mx.lookupHTTPSSvcUDPForeign(ctx, t)
				wg.Done()
			}()
		}

	}
	wg.Wait()
}

func (mx *Measurer) lookupHostForeign(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := saver.WrapResolver(t.foreignResolver())
	defer r.CloseIdleConnections()
	_, _ = mx.doLookupHost(ctx, t.targetDomain(), r) // ignore return value
	return mx.newDNSLookupMeasurement(t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHTTPSSvcUDPForeign(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := saver.WrapResolver(t.foreignResolver())
	defer r.CloseIdleConnections()
	_, _ = mx.doLookupHTTPSSvc(ctx, t.targetDomain(), r) // ignore return value
	return mx.newDNSLookupMeasurement(t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHostSystem(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverSystem(saver)
	defer r.CloseIdleConnections()
	_, _ = mx.doLookupHost(ctx, t.targetDomain(), r) // ignore return value
	return mx.newDNSLookupMeasurement(t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHostUDP(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.resolverAddress())
	defer r.CloseIdleConnections()
	_, _ = mx.doLookupHost(ctx, t.targetDomain(), r) // ignore return value
	return mx.newDNSLookupMeasurement(t, saver.MoveOutTrace())
}

func (mx *Measurer) lookupHTTPSSvcUDP(
	ctx context.Context, t *dnsLookupTarget) *DNSLookupMeasurement {
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, t.resolverAddress())
	defer r.CloseIdleConnections()
	_, _ = mx.doLookupHTTPSSvc(ctx, t.targetDomain(), r) // ignore return value
	return mx.newDNSLookupMeasurement(t, saver.MoveOutTrace())
}

func (mx *Measurer) doLookupHost(
	ctx context.Context, domain string, r model.Resolver) ([]string, error) {
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with %s resolver", domain, r.Network())
	timeout := mx.DNSLookupTimeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return addrs, err
}

func (mx *Measurer) doLookupHTTPSSvc(
	ctx context.Context, domain string, r model.Resolver) (*model.HTTPSSvc, error) {
	ol := NewOperationLogger(mx.Logger, "LookupHTTPSvc %s with %s resolver", domain, r.Network())
	timeout := mx.DNSLookupTimeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	https, err := r.LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return https, err
}

func (mx *Measurer) newDNSLookupMeasurement(
	t *dnsLookupTarget, trace *archival.Trace) *DNSLookupMeasurement {
	out := &DNSLookupMeasurement{
		Domain:           t.targetDomain(),
		URLMeasurementID: t.plan.URLMeasurementID,
		ID:               mx.NextID(),
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
