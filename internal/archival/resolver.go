package archival

//
// Saves DNS lookup events
//

import (
	"context"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// LookupHost performs a host lookup with the given resolver
// and saves the results into the saver.
func (s *Saver) LookupHost(ctx context.Context, reso model.Resolver, domain string) ([]string, error) {
	started := time.Now()
	addrs, err := reso.LookupHost(ctx, domain)
	s.appendLookupHostEvent(&FlatDNSLookupEvent{
		ALPNs:           nil,
		Addresses:       addrs,
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      "getaddrinfo",
		ResolverAddress: reso.Address(),
		ResolverNetwork: reso.Network(),
		Started:         started,
	})
	return addrs, err
}

func (s *Saver) appendLookupHostEvent(ev *FlatDNSLookupEvent) {
	s.mu.Lock()
	s.trace.DNSLookupHost = append(s.trace.DNSLookupHost, ev)
	s.mu.Unlock()
}

// LookupHTTPS performs an HTTPSSvc-record lookup using the given
// resolver and saves the results into the saver.
func (s *Saver) LookupHTTPS(ctx context.Context, reso model.Resolver, domain string) (*model.HTTPSSvc, error) {
	started := time.Now()
	https, err := reso.LookupHTTPS(ctx, domain)
	s.appendLookupHTTPSEvent(&FlatDNSLookupEvent{
		ALPNs:           s.safeALPNs(https),
		Addresses:       s.safeAddresses(https),
		Domain:          domain,
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		LookupType:      "https",
		ResolverAddress: reso.Address(),
		ResolverNetwork: reso.Network(),
		Started:         started,
	})
	return https, err
}

func (s *Saver) appendLookupHTTPSEvent(ev *FlatDNSLookupEvent) {
	s.mu.Lock()
	s.trace.DNSLookupHTTPS = append(s.trace.DNSLookupHTTPS, ev)
	s.mu.Unlock()
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

// DNSRoundTrip implements ArchivalSaver.DNSRoundTrip.
func (s *Saver) DNSRoundTrip(ctx context.Context, txp model.DNSTransport, query []byte) ([]byte, error) {
	started := time.Now()
	reply, err := txp.RoundTrip(ctx, query)
	s.appendDNSRoundTripEvent(&FlatDNSRoundTripEvent{
		Address:  txp.Address(),
		Failure:  NewFlatFailure(err),
		Finished: time.Now(),
		Network:  txp.Network(),
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
