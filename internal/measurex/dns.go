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

// DNSLookup describes a DNS lookup we want to perform.
type DNSLookup struct {
	// URL is the URL to resolve.
	URL *url.URL

	// Resolvers describes the resolvers to use.
	Resolvers []*DNSResolverInfo
}

// DNSLookupMeasurement is a DNS measurement.
type DNSLookupMeasurement struct {
	// Domain is the domain this measurement refers to.
	Domain string

	// ID is the unique ID of this measurement.
	ID int64

	// Failure is the failure that occurred.
	Failure archival.FlatFailure

	// Addresses contains the resolved addresses.
	Addresses []string

	// ALPNs contains the available ALPNs.
	ALPNs []string

	// A DNSMeasurement contains a trace.
	*archival.Trace
}

// dnsLookupPair contains a single URL and single resolver.
type dnsLookupPair struct {
	r *DNSResolverInfo
	u *url.URL
}

// MeasureDNSLookup performs DNS queries in parallel.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
func (mx *Measurer) MeasureDNSLookup(ctx context.Context, parallelism int,
	dnsLookups ...*DNSLookup) <-chan *DNSLookupMeasurement {
	var (
		done   = make(chan interface{})
		output = make(chan *DNSLookupMeasurement)
		pairs  = make(chan *dnsLookupPair)
	)
	go func() {
		defer close(pairs)
		for _, lookup := range dnsLookups {
			for _, r := range lookup.Resolvers {
				pairs <- &dnsLookupPair{
					r: r,
					u: lookup.URL,
				}
			}
		}
	}()
	if parallelism <= 0 {
		parallelism = 4
	}
	for i := 0; i < parallelism; i++ {
		go func() {
			for pair := range pairs {
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
	p *dnsLookupPair, output chan<- *DNSLookupMeasurement) {
	wg := &sync.WaitGroup{}
	switch {
	case p.r.Network == DNSResolverSystem:
		output <- mx.lookupHostSystem(ctx, p.u.Hostname())
	case p.r.Network == DNSResolverUDP && p.u.Scheme != "https":
		output <- mx.lookupHostUDP(ctx, p.u.Hostname(), p.r.Address)
	case p.r.Network == DNSResolverUDP && p.u.Scheme == "https":
		wg.Add(2)
		go func() {
			output <- mx.lookupHostUDP(ctx, p.u.Hostname(), p.r.Address)
			wg.Done()
		}()
		go func() {
			output <- mx.lookupHTTPSSvcUDP(ctx, p.u.Hostname(), p.r.Address)
			wg.Done()
		}()
	case p.r.Network == DNSResolverForeign && p.u.Scheme != "https":
		output <- mx.lookupHostForeign(ctx, p.u.Hostname(), p.r.ForeignResolver)
	case p.r.Network == DNSResolverForeign && p.u.Scheme == "https":
		wg.Add(2)
		go func() {
			output <- mx.lookupHostForeign(ctx, p.u.Hostname(), p.r.ForeignResolver)
			wg.Done()
		}()
		go func() {
			output <- mx.lookupHTTPSSvcUDPForeign(ctx, p.u.Hostname(), p.r.ForeignResolver)
			wg.Done()
		}()
	}
	wg.Wait()
}

// lookupHostForeign performs a LookupHost using a "foreign" resolver.
func (mx *Measurer) lookupHostForeign(
	ctx context.Context, domain string, r model.Resolver) *DNSLookupMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with %s", domain, r.Network())
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	addrs, err := saver.WrapResolver(r).LookupHost(ctx, domain)
	ol.Stop(err)
	return mx.newDNSLookupMeasurement(domain, addrs, err, saver.MoveOutTrace())
}

// lookupHTTPSSvcUDPForeign is like LookupHTTPSSvcUDP
// except that it uses a "foreign" resolver.
func (mx *Measurer) lookupHTTPSSvcUDPForeign(
	ctx context.Context, domain string, r model.Resolver) *DNSLookupMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHTTPSvc %s with %s", domain, r.Address())
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	https, err := saver.WrapResolver(r).LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return mx.newDNSLookupMeasurementHTTPS(domain, https, err, saver.MoveOutTrace())
}

// newDNSLookupMeasurement creates a new DNS measurement from a given
// domain to measure and a trace containing results.
func (mx *Measurer) newDNSLookupMeasurement(domain string,
	addrs []string, err error, trace *archival.Trace) *DNSLookupMeasurement {
	return &DNSLookupMeasurement{
		Domain:    domain,
		ID:        mx.IDGenerator.Next(),
		Failure:   archival.NewFlatFailure(err),
		Addresses: addrs,
		Trace:     trace,
	}
}

// newDNSLookupMeasurementHTTPS is like newDNSLookupMeasurement but
// takes in input an HTTPSSvc instead of a list of addresses.
func (mx *Measurer) newDNSLookupMeasurementHTTPS(domain string,
	https *model.HTTPSSvc, err error, trace *archival.Trace) *DNSLookupMeasurement {
	var (
		addrs []string
		alpns []string
	)
	if https != nil {
		addrs = append(addrs, https.IPv4...)
		addrs = append(addrs, https.IPv6...)
		alpns = https.ALPN
	}
	return &DNSLookupMeasurement{
		Domain:    domain,
		ID:        mx.IDGenerator.Next(),
		Failure:   archival.NewFlatFailure(err),
		Addresses: addrs,
		ALPNs:     alpns,
		Trace:     trace,
	}
}

// lookupHostSystem performs a LookupHost using the system resolver.
func (mx *Measurer) lookupHostSystem(ctx context.Context, domain string) *DNSLookupMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with getaddrinfo", domain)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	r := mx.Library.NewResolverSystem(saver)
	defer r.CloseIdleConnections()
	addrs, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return mx.newDNSLookupMeasurement(domain, addrs, err, saver.MoveOutTrace())
}

// lookupHostUDP is like LookupHostSystem but uses an UDP resolver.
//
// Arguments:
//
// - ctx is the context allowing to timeout the operation;
//
// - domain is the domain to resolve (e.g., "x.org");
//
// - address is the UDP resolver address (e.g., "dns.google:53").
//
// Returns a DNSMeasurement.
func (mx *Measurer) lookupHostUDP(
	ctx context.Context, domain, address string) *DNSLookupMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with %s/udp", domain, address)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, address)
	defer r.CloseIdleConnections()
	addrs, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return mx.newDNSLookupMeasurement(domain, addrs, err, saver.MoveOutTrace())
}

// lookupHTTPSSvcUDP issues an HTTPSSvc query for the given domain.
//
// Arguments:
//
// - ctx is the context allowing to timeout the operation;
//
// - domain is the domain to resolve (e.g., "x.org");
//
// - address is the UDP resolver address (e.g., "dns.google:53").
//
// Returns a DNSMeasurement.
func (mx *Measurer) lookupHTTPSSvcUDP(
	ctx context.Context, domain, address string) *DNSLookupMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHTTPSvc %s with %s/udp", domain, address)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, address)
	defer r.CloseIdleConnections()
	https, err := r.LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return mx.newDNSLookupMeasurementHTTPS(domain, https, err, saver.MoveOutTrace())
}
