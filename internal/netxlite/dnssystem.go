package netxlite

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/miekg/dns"
)

// DNSSystemResolver is a resolver using DNSSystemTransport.
type DNSSystemResolver struct {
	// decoder is the DNS decoder to use.
	decoder model.DNSDecoder

	// encoder is the DNS encoder to use.
	encoder model.DNSEncoder

	// txp is the underlying transport to use.
	txp model.DNSTransport
}

var _ model.Resolver = &DNSSystemResolver{}

// NewDNSSystemResolver creates a new DNSSystemResolver instance
// using the given DNSSystemTransport instance.
func NewDNSSystemResolver(txp model.DNSTransport) *DNSSystemResolver {
	if txp.Network() != "system" {
		logcat.Bugf("using NewDNSSystemResolver with non-system transport")
	}
	return &DNSSystemResolver{
		decoder: &DNSDecoderMiekg{},
		encoder: &DNSEncoderMiekg{},
		txp:     txp,
	}
}

// LookupHost implements Resolver.LookupHost.
func (r *DNSSystemResolver) LookupHost(
	ctx context.Context, hostname string) (addrs []string, err error) {
	rawQuery, queryID, err := r.encoder.EncodeQuery(hostname, dns.TypeANY, false)
	if err != nil {
		return nil, err
	}
	rawReply, err := r.txp.RoundTrip(ctx, rawQuery)
	if err != nil {
		return nil, err
	}
	return r.decoder.DecodeLookupHost(dns.TypeANY, rawReply, queryID)
}

// Network implements Resolver.Network.
func (r *DNSSystemResolver) Network() string {
	return r.txp.Network()
}

// Address implements Resolver.Address.
func (r *DNSSystemResolver) Address() string {
	return r.txp.Address()
}

// CloseIdleConnections implements Resolver.CloseIdleConnections.
func (r *DNSSystemResolver) CloseIdleConnections() {
	r.txp.CloseIdleConnections()
}

// ErrDNSNotImplemented indicates that a given query is not implemented.
var ErrDNSNotImplemented = errors.New("ooresolver: DNS query not implemented")

// LookupHTTPS implements DNSResolver.LookupHTTPS.
func (r *DNSSystemResolver) LookupHTTPS(
	ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	return nil, ErrDNSNotImplemented
}

// LookupNS implements DNSResolver.LookupNS.
func (r *DNSSystemResolver) LookupNS(
	ctx context.Context, domain string) ([]*net.NS, error) {
	return nil, ErrDNSNotImplemented
}

// LookupPTR implements DNSResolver.LookupPTR.
func (r *DNSSystemResolver) LookupPTR(
	ctx context.Context, domain string) ([]string, error) {
	return nil, ErrDNSNotImplemented
}

// DNSSystemTransport is a transport that uses getaddrinfo or
// the go standard library to perform a DNS resolution.
type DNSSystemTransport struct {
	// decoder is the DNS decoder to use.
	decoder model.DNSDecoder

	// encoder is the DNS encoder to use.
	encoder model.DNSEncoder

	// testableLookupHost allows to override LookupHost in testing.
	testableLookupHost func(ctx context.Context, domain string) ([]string, error)

	// testableTimeout allows to override timeout in testing.
	testableTimeout time.Duration
}

// NewDNSSystemTransport returns a new DNSSystemTransport.
func NewDNSSystemTransport() *DNSSystemTransport {
	return &DNSSystemTransport{
		decoder:            &DNSDecoderMiekg{},
		encoder:            &DNSEncoderMiekg{},
		testableLookupHost: nil,
		testableTimeout:    0,
	}
}

var _ model.DNSTransport = &DNSSystemTransport{}

var (
	// errDNSExpectedSingleQuestion is returned when the code expected to receive
	// a query containing a single question and got zero or more than one.
	errDNSExpectedSingleQuestion = errors.New("ooniresolver: expected single questions")

	// errDNSExpectedANY means we expected to see an ANY query.
	errDNSExpectedANY = errors.New("ooniresolver: expecte a query for ANY")
)

// RoundTrip implements DNSTransport.RoundTrip. This function expects in
// input a single query for dns.ANY and performs a DNS lookup using the
// system resolver. It returns all the found records. Obviously, the returned
// DNS reply is a fake reply different from the queries sent on the wire.
func (txp *DNSSystemTransport) RoundTrip(
	ctx context.Context, query []byte) (reply []byte, err error) {
	domain, dq, err := txp.parseQuery(query)
	if err != nil {
		return nil, err
	}
	addrs, err := txp.lookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	return txp.newFakeReply(dq, addrs)
}

func (txp *DNSSystemTransport) parseQuery(query []byte) (string, *dns.Msg, error) {
	dq, err := txp.decoder.ParseQuery(query)
	if err != nil {
		return "", nil, err
	}
	if len(dq.Question) != 1 {
		return "", nil, errDNSExpectedSingleQuestion
	}
	q0 := dq.Question[0]
	if q0.Qtype != dns.TypeANY {
		return "", nil, errDNSExpectedANY
	}
	name := q0.Name
	if len(name) > 0 && strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	return name, dq, nil
}

func (txp *DNSSystemTransport) lookupHost(
	ctx context.Context, domain string) ([]string, error) {
	// This code forces adding a shorter timeout to the domain name
	// resolutions when using the system resolver. We have seen cases
	// in which such a timeout becomes too large. One such case is
	// described in https://github.com/ooni/probe/issues/1726.
	addrsch, errch := make(chan []string, 1), make(chan error, 1)
	ctx, cancel := context.WithTimeout(ctx, txp.timeout())
	defer cancel()
	go func() {
		addrs, err := txp.lookupHostFunc()(ctx, domain)
		if err != nil {
			errch <- err
			return
		}
		addrsch <- addrs
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case addrs := <-addrsch:
		return addrs, nil
	case err := <-errch:
		return nil, err
	}
}

func (txp *DNSSystemTransport) timeout() time.Duration {
	if txp.testableTimeout > 0 {
		return txp.testableTimeout
	}
	return 15 * time.Second
}

func (txp *DNSSystemTransport) lookupHostFunc() func(
	ctx context.Context, domain string) ([]string, error) {
	if txp.testableLookupHost != nil {
		return txp.testableLookupHost
	}
	return TProxy.LookupHost
}

func (txp *DNSSystemTransport) newFakeReply(query *dns.Msg, addrs []string) ([]byte, error) {
	reply, err := txp.encoder.EncodeReply(query, addrs)
	if err != nil {
		return nil, err
	}
	return reply.Pack()
}

// RequiresPadding implements DNSTransport.RequiresPadding.
func (txp *DNSSystemTransport) RequiresPadding() bool {
	return false
}

// Network implements DNSTransport.Network.
func (txp *DNSSystemTransport) Network() string {
	return "system"
}

// Address implements DNSTransport.Address.
func (txp *DNSSystemTransport) Address() string {
	return ""
}

// CloseIdleConnections closes idle connections, if any.
func (txp *DNSSystemTransport) CloseIdleConnections() {
	// nothing to do
}
