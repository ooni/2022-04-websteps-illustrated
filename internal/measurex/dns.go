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

	"github.com/bassosimone/websteps-illustrated/internal/archival"
)

// DNSMeasurement is a DNS measurement.
type DNSMeasurement struct {
	// Domain is the domain this measurement refers to.
	Domain string

	// ID is the unique ID of this measurement.
	ID int64

	// A DNSMeasurement contains a trace.
	*archival.Trace
}

// newDNSMeasurement creates a new DNS measurement from a given
// domain to measure and a trace containing results.
func (mx *Measurer) newDNSMeasurement(domain string, trace *archival.Trace) *DNSMeasurement {
	return &DNSMeasurement{
		Domain: domain,
		ID:     mx.IDGenerator.Add(1),
		Trace:  trace,
	}
}

// LookupHostSystem performs a LookupHost using the system resolver.
func (mx *Measurer) LookupHostSystem(ctx context.Context, domain string) *DNSMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with getaddrinfo", domain)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	r := mx.Library.NewResolverSystem(saver)
	defer r.CloseIdleConnections()
	_, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return mx.newDNSMeasurement(domain, saver.MoveOutTrace())
}

// LookupHostUDP is like LookupHostSystem but uses an UDP resolver.
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
func (mx *Measurer) LookupHostUDP(
	ctx context.Context, domain, address string) *DNSMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with %s/udp", domain, address)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, address)
	defer r.CloseIdleConnections()
	_, err := r.LookupHost(ctx, domain)
	ol.Stop(err)
	return mx.newDNSMeasurement(domain, saver.MoveOutTrace())
}

// LookupHTTPSSvcUDP issues an HTTPSSvc query for the given domain.
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
func (mx *Measurer) LookupHTTPSSvcUDP(
	ctx context.Context, domain, address string) *DNSMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHTTPSvc %s with %s/udp", domain, address)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	r := mx.Library.NewResolverUDP(saver, address)
	defer r.CloseIdleConnections()
	_, err := r.LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return mx.newDNSMeasurement(domain, saver.MoveOutTrace())
}
