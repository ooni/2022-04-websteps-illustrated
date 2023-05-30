package archival

//
// Saves DNS lookup events
//

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
)

// DNSLookupType indicates the type of DNS lookup.
type DNSLookupType string

var (
	// DNSLookupTypeGetaddrinfo indicates a getaddrinfo like lookup where we
	// issue a query for A and a query for AAAA.
	DNSLookupTypeGetaddrinfo = DNSLookupType("getaddrinfo")

	// DNSLookupTypeHTTPS indicates we're performing an HTTPS lookup.
	DNSLookupTypeHTTPS = DNSLookupType("https")

	// DNSLookupTypeNS indicates we're performing a NS lookup type.
	DNSLookupTypeNS = DNSLookupType("ns")

	// DNSLookupTypeReverse indicates we're performing a reverse lookup.
	DNSLookupTypeReverse = DNSLookupType("reverse")
)

// WrapResolver wraps a resolver to use the saver.
func (s *Saver) WrapResolver(reso model.Resolver) model.Resolver {
	return &resolverSaver{
		r: reso,
		s: s,
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
	r model.Resolver
	s *Saver
}

var _ model.Resolver = &resolverSaver{}

func (r *resolverSaver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	return r.s.lookupHost(ctx, r.r, domain)
}

func (r *resolverSaver) LookupHTTPS(ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	return r.s.lookupHTTPS(ctx, r.r, domain)
}

func (r *resolverSaver) LookupNS(ctx context.Context, domain string) ([]*net.NS, error) {
	return r.s.lookupNS(ctx, r.r, domain)
}

func (r *resolverSaver) LookupPTR(ctx context.Context, domain string) ([]string, error) {
	return r.s.lookupPTR(ctx, r.r, domain)
}

func (r *resolverSaver) Address() string {
	return r.r.Address()
}

func (r *resolverSaver) Network() string {
	return r.r.Network()
}

func (r *resolverSaver) CloseIdleConnections() {
	r.r.CloseIdleConnections()
}

func (s *Saver) lookupHost(ctx context.Context, reso model.Resolver, domain string) ([]string, error) {
	started := time.Now()
	addrs, err := reso.LookupHost(ctx, domain)
	s.appendDNSLookupEvent(&FlatDNSLookupEvent{
		ALPNs:           nil,
		Addresses:       addrs,
		CNAME:           "",
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      DNSLookupTypeGetaddrinfo,
		NS:              nil,
		PTRs:            nil,
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
		CNAME:           "",
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      DNSLookupTypeHTTPS,
		NS:              nil,
		PTRs:            nil,
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

func (s *Saver) lookupNS(ctx context.Context, reso model.Resolver, domain string) ([]*net.NS, error) {
	started := time.Now()
	ns, err := reso.LookupNS(ctx, domain)
	s.appendDNSLookupEvent(&FlatDNSLookupEvent{
		ALPNs:           nil,
		Addresses:       nil,
		CNAME:           "",
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      DNSLookupTypeNS,
		NS:              s.ns(ns),
		PTRs:            nil,
		ResolverAddress: reso.Address(),
		ResolverNetwork: NetworkType(reso.Network()),
		Started:         started,
	})
	return ns, err
}

func (s *Saver) ns(ns []*net.NS) (out []string) {
	for _, e := range ns {
		out = append(out, e.Host)
	}
	return
}

func (s *Saver) lookupPTR(ctx context.Context, reso model.Resolver, domain string) ([]string, error) {
	started := time.Now()
	domains, err := reso.LookupPTR(ctx, domain)
	s.appendDNSLookupEvent(&FlatDNSLookupEvent{
		ALPNs:           nil,
		Addresses:       nil,
		CNAME:           "",
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      DNSLookupTypeReverse,
		NS:              []string{},
		PTRs:            domains,
		ResolverAddress: reso.Address(),
		ResolverNetwork: NetworkType(reso.Network()),
		Started:         started,
	})
	return domains, err
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
		ResolverAddress: txp.Address(),
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		ResolverNetwork: NetworkType(txp.Network()),
		Query:           query,
		Reply:           reply,
		Started:         started,
	})
	return reply, err
}

func (s *Saver) appendDNSRoundTripEvent(ev *FlatDNSRoundTripEvent) {
	s.mu.Lock()
	s.trace.DNSRoundTrip = append(s.trace.DNSRoundTrip, ev)
	s.mu.Unlock()
}

// MaybeGatherCNAME tries to read the CNAME from DNSRoundTripEvents. If there is
// zero or more than one CNAMEs in the reply, we return an empty string.
func MaybeGatherCNAME(rts []*FlatDNSRoundTripEvent) string {
	cnames := maybeGatherCNAMEs(&netxlite.DNSDecoderMiekg{}, rts)
	if len(cnames) != 1 {
		return ""
	}
	return cnames[0]
}

// maybeGatherCNAMEs returns the unique CNAMEs in the reply.
func maybeGatherCNAMEs(decoder model.DNSDecoder, rts []*FlatDNSRoundTripEvent) (out []string) {
	cnames := map[string]int{}
	for _, rt := range rts {
		if len(rt.Reply) <= 0 {
			continue
		}
		msg, err := decoder.ParseReply(rt.Reply)
		if err != nil {
			continue
		}
		for _, ans := range msg.Answer {
			switch avalue := ans.(type) {
			case *dns.CNAME:
				cnames[avalue.Target]++
			}
		}
	}
	for key := range cnames {
		out = append(out, key)
	}
	return
}
