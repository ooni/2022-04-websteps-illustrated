package netxlite

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/atomicx"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
)

// ParallelResolver uses a transport and sends performs a LookupHost
// operation in a parallel fashion, hence its name.
//
// You should probably use NewUnwrappedParallel to create a new instance.
type ParallelResolver struct {
	// Encoder is the MANDATORY encoder to use.
	Encoder model.DNSEncoder

	// Decoder is the MANDATORY decoder to use.
	Decoder model.DNSDecoder

	// NumTimeouts is MANDATORY and counts the number of timeouts.
	NumTimeouts *atomicx.Int64

	// Txp is the underlying DNS transport.
	Txp model.DNSTransport
}

// UnwrappedParallelResolver creates a new ParallelResolver instance.
func NewUnwrappedParallelResolver(t model.DNSTransport) *ParallelResolver {
	return &ParallelResolver{
		Encoder:     &DNSEncoderMiekg{},
		Decoder:     &DNSDecoderMiekg{},
		NumTimeouts: &atomicx.Int64{},
		Txp:         t,
	}
}

// Transport returns the transport being used.
func (r *ParallelResolver) Transport() model.DNSTransport {
	return r.Txp
}

// Network returns the "network" of the underlying transport.
func (r *ParallelResolver) Network() string {
	return r.Txp.Network()
}

// Address returns the "address" of the underlying transport.
func (r *ParallelResolver) Address() string {
	return r.Txp.Address()
}

// CloseIdleConnections closes idle connections, if any.
func (r *ParallelResolver) CloseIdleConnections() {
	r.Txp.CloseIdleConnections()
}

// LookupHost performs an A lookup followed by an AAAA lookup for hostname.
func (r *ParallelResolver) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	resch := make(chan *parallelResolverResult)
	go r.lookupHost(ctx, hostname, dns.TypeA, resch)
	go r.lookupHost(ctx, hostname, dns.TypeAAAA, resch)
	first := <-resch
	second := <-resch
	if first.err != nil && second.err != nil {
		// Note: we choose to return the A error because we assume that
		// it's the more meaningful one: the AAAA error may just be telling
		// us that there is no AAAA record for the website.
		if first.qtype == dns.TypeA {
			return nil, first.err
		}
		return nil, second.err
	}
	var addrs []string
	addrs = append(addrs, first.addrs...)
	addrs = append(addrs, second.addrs...)
	return addrs, nil
}

// LookupHTTPS implements Resolver.LookupHTTPS.
func (r *ParallelResolver) LookupHTTPS(
	ctx context.Context, hostname string) (*model.HTTPSSvc, error) {
	querydata, queryID, err := r.Encoder.EncodeQuery(
		hostname, dns.TypeHTTPS, r.Txp.RequiresPadding())
	if err != nil {
		return nil, err
	}
	replydata, err := r.Txp.RoundTrip(ctx, querydata)
	if err != nil {
		return nil, err
	}
	return r.Decoder.DecodeLookupHTTPS(replydata, queryID)
}

// parallelResolverResult is the internal representation of a lookup result.
type parallelResolverResult struct {
	addrs []string
	err   error
	qtype uint16
}

// lookupHost issues a lookup host query for the specified qtype (e.g., dns.A).
func (r *ParallelResolver) lookupHost(ctx context.Context, hostname string,
	qtype uint16, out chan<- *parallelResolverResult) {
	querydata, queryID, err := r.Encoder.EncodeQuery(hostname, qtype, r.Txp.RequiresPadding())
	if err != nil {
		out <- &parallelResolverResult{
			addrs: []string{},
			err:   err,
			qtype: qtype,
		}
		return
	}
	replydata, err := r.Txp.RoundTrip(ctx, querydata)
	if err != nil {
		out <- &parallelResolverResult{
			addrs: []string{},
			err:   err,
			qtype: qtype,
		}
		return
	}
	addrs, err := r.Decoder.DecodeLookupHost(qtype, replydata, queryID)
	out <- &parallelResolverResult{
		addrs: addrs,
		err:   err,
		qtype: qtype,
	}
}

// LookupNS implements Resolver.LookupNS.
func (r *ParallelResolver) LookupNS(
	ctx context.Context, hostname string) ([]*net.NS, error) {
	querydata, queryID, err := r.Encoder.EncodeQuery(
		hostname, dns.TypeNS, r.Txp.RequiresPadding())
	if err != nil {
		return nil, err
	}
	replydata, err := r.Txp.RoundTrip(ctx, querydata)
	if err != nil {
		return nil, err
	}
	return r.Decoder.DecodeLookupNS(replydata, queryID)
}

// LookupPTR implements Resolver.LookupPTR.
func (r *ParallelResolver) LookupPTR(
	ctx context.Context, hostname string) ([]string, error) {
	querydata, queryID, err := r.Encoder.EncodeQuery(
		hostname, dns.TypePTR, r.Txp.RequiresPadding())
	if err != nil {
		return nil, err
	}
	replydata, err := r.Txp.RoundTrip(ctx, querydata)
	if err != nil {
		return nil, err
	}
	return r.Decoder.DecodeLookupPTR(replydata, queryID)
}
