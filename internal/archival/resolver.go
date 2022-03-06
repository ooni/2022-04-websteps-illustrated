package archival

//
// Saves DNS lookup events
//

import (
	"context"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// DNSLookupType indicates the type of DNS lookup.
type DNSLookupType string

var (
	// DNSLookupTypeGetaddrinfo indicates a getaddrinfo like lookup where we
	// issue a query for A and a query for AAAA.
	DNSLookupTypeGetaddrinfo = DNSLookupType("getaddrinfo")

	// DNSLookupTypeHTTPS indicates we're performing an HTTPS lookup.
	DNSLookupTypeHTTPS = DNSLookupType("https")
)

// WrapResolver wraps a resolver to use the saver.
func (s *Saver) WrapResolver(reso model.Resolver) model.Resolver {
	return &resolverSaver{
		Resolver: reso,
		s:        s,
	}
}

// WrapDNSTransport wraps a DNS transport to use the saver.
func (s *Saver) WrapDNSTransport(txp model.DNSTransport) model.DNSTransport {
	return &dnsTransportSaver{
		DNSTransport: txp,
		s:            s,
	}
}

type resolverSaver struct {
	model.Resolver
	s *Saver
}

func (r *resolverSaver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	return r.s.lookupHost(ctx, r.Resolver, domain)
}

func (r *resolverSaver) LookupHTTPS(ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	return r.s.lookupHTTPS(ctx, r.Resolver, domain)
}

func (s *Saver) lookupHost(ctx context.Context, reso model.Resolver, domain string) ([]string, error) {
	started := time.Now()
	addrs, err := reso.LookupHost(ctx, domain)
	s.appendDNSLookupEvent(&FlatDNSLookupEvent{
		ALPNs:           nil,
		Addresses:       addrs,
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      DNSLookupTypeGetaddrinfo,
		ResolverAddress: reso.Address(),
		ResolverNetwork: NetworkType(reso.Network()),
		Started:         started,
	})
	return addrs, err
}

func (s *Saver) appendDNSLookupEvent(ev *FlatDNSLookupEvent) {
	s.mu.Lock()
	s.trace.DNSLookup = append(s.trace.DNSLookup, ev)
	s.mu.Unlock()
}

func (s *Saver) lookupHTTPS(ctx context.Context, reso model.Resolver, domain string) (*model.HTTPSSvc, error) {
	started := time.Now()
	https, err := reso.LookupHTTPS(ctx, domain)
	s.appendDNSLookupEvent(&FlatDNSLookupEvent{
		ALPNs:           s.safeALPNs(https),
		Addresses:       s.safeAddresses(https),
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      DNSLookupTypeHTTPS,
		ResolverAddress: reso.Address(),
		ResolverNetwork: NetworkType(reso.Network()),
		Started:         started,
	})
	return https, err
}

func (s *Saver) safeALPNs(https *model.HTTPSSvc) (out []string) {
	if https != nil {
		out = https.ALPN
	}
	return
}

func (s *Saver) safeAddresses(https *model.HTTPSSvc) (out []string) {
	if https != nil {
		out = append(out, https.IPv4...)
		out = append(out, https.IPv6...)
	}
	return
}

type dnsTransportSaver struct {
	model.DNSTransport
	s *Saver
}

func (txp *dnsTransportSaver) RoundTrip(ctx context.Context, query []byte) ([]byte, error) {
	return txp.s.dnsRoundTrip(ctx, txp.DNSTransport, query)
}

func (s *Saver) dnsRoundTrip(ctx context.Context, txp model.DNSTransport, query []byte) ([]byte, error) {
	started := time.Now()
	reply, err := txp.RoundTrip(ctx, query)
	s.appendDNSRoundTripEvent(&FlatDNSRoundTripEvent{
		Address:  txp.Address(),
		Failure:  NewFlatFailure(err),
		Finished: time.Now(),
		Network:  NetworkType(txp.Network()),
		Query:    query,
		Reply:    reply,
		Started:  started,
	})
	return reply, err
}

func (s *Saver) appendDNSRoundTripEvent(ev *FlatDNSRoundTripEvent) {
	s.mu.Lock()
	s.trace.DNSRoundTrip = append(s.trace.DNSRoundTrip, ev)
	s.mu.Unlock()
}
