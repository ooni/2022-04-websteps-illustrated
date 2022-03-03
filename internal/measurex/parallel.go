package measurex

import (
	"context"
	"net/url"
	"sync"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

//
// Parallel measurer
//

// LookupHostParallel is like LookupURLHostParallel but we only
// have in input an hostname rather than a URL. As such, we cannot
// determine whether to perform HTTPSSvc lookups and so we aren't
// going to perform this kind of lookups in this case.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
func (mx *Measurer) LookupHostParallel(ctx context.Context,
	parallelism int, hostname string) <-chan *DNSMeasurement {
	URL := &url.URL{
		Scheme: "", // so we don't see https and we don't try HTTPSSvc
		Host:   hostname,
	}
	return mx.LookupURLHostParallel(ctx, parallelism, URL)
}

// ResolverNetwork identifies the network of a resolver.
type ResolverNetwork string

var (
	// ResolverSystem is the system resolver (i.e., getaddrinfo)
	ResolverSystem = ResolverNetwork("system")

	// ResolverUDP is a resolver using DNS-over-UDP
	ResolverUDP = ResolverNetwork("udp")

	// ResolverForeign is a resolver that is not managed by
	// this package. We can wrap it, but we don't be able to
	// observe any event but Lookup{Host,HTTPSvc}
	ResolverForeign = ResolverNetwork("foreign")
)

// ResolverInfo contains info about a DNS resolver.
type ResolverInfo struct {
	// Network is the resolver's network (e.g., "doh", "udp")
	Network ResolverNetwork

	// Address is the address (e.g., "1.1.1.1:53", "https://1.1.1.1/dns-query")
	Address string

	// ForeignResolver is only used when Network's
	// value equals the ResolverForeign constant.
	ForeignResolver model.Resolver
}

// LookupURLHostParallel performs an LookupHost-like operation for each
// resolver that you provide as argument using a pool of goroutines.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
func (mx *Measurer) LookupURLHostParallel(ctx context.Context, parallelism int,
	URL *url.URL, resos ...*ResolverInfo) <-chan *DNSMeasurement {
	var (
		done      = make(chan interface{})
		resolvers = make(chan *ResolverInfo)
		output    = make(chan *DNSMeasurement)
	)
	go func() {
		defer close(resolvers)
		for _, reso := range resos {
			resolvers <- reso
		}
	}()
	if parallelism <= 0 {
		parallelism = 4
	}
	for i := 0; i < parallelism; i++ {
		go func() {
			for reso := range resolvers {
				mx.lookupHostWithResolverInfo(ctx, reso, URL, output)
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

func (mx *Measurer) lookupHostWithResolverInfo(
	ctx context.Context, r *ResolverInfo, URL *url.URL,
	output chan<- *DNSMeasurement) {
	wg := &sync.WaitGroup{}
	switch {
	case r.Network == ResolverSystem:
		output <- mx.LookupHostSystem(ctx, URL.Hostname())
	case r.Network == ResolverUDP && URL.Scheme != "https":
		output <- mx.LookupHostUDP(ctx, URL.Hostname(), r.Address)
	case r.Network == ResolverUDP && URL.Scheme == "https":
		wg.Add(2)
		go func() {
			output <- mx.LookupHostUDP(ctx, URL.Hostname(), r.Address)
			wg.Done()
		}()
		go func() {
			output <- mx.LookupHTTPSSvcUDP(ctx, URL.Hostname(), r.Address)
			wg.Done()
		}()
	case r.Network == ResolverForeign && URL.Scheme != "https":
		output <- mx.lookupHostForeign(ctx, URL.Hostname(), r.ForeignResolver)
	case r.Network == ResolverForeign && URL.Scheme == "https":
		wg.Add(2)
		go func() {
			output <- mx.lookupHostForeign(ctx, URL.Hostname(), r.ForeignResolver)
			wg.Done()
		}()
		go func() {
			output <- mx.lookupHTTPSSvcUDPForeign(ctx, URL.Hostname(), r.ForeignResolver)
			wg.Done()
		}()
	}
	wg.Wait()
}

// lookupHostForeign performs a LookupHost using a "foreign" resolver.
func (mx *Measurer) lookupHostForeign(
	ctx context.Context, domain string, r model.Resolver) *DNSMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHost %s with %s", domain, r.Network())
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	_, err := saver.WrapResolver(r).LookupHost(ctx, domain)
	ol.Stop(err)
	return mx.newDNSMeasurement(domain, saver.MoveOutTrace())
}

// lookupHTTPSSvcUDPForeign is like LookupHTTPSSvcUDP
// except that it uses a "foreign" resolver.
func (mx *Measurer) lookupHTTPSSvcUDPForeign(
	ctx context.Context, domain string, r model.Resolver) *DNSMeasurement {
	timeout := mx.DNSLookupTimeout
	ol := NewOperationLogger(mx.Logger, "LookupHTTPSvc %s with %s", domain, r.Address())
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	saver := archival.NewSaver()
	_, err := saver.WrapResolver(r).LookupHTTPS(ctx, domain)
	ol.Stop(err)
	return mx.newDNSMeasurement(domain, saver.MoveOutTrace())
}

// HTTPEndpointGetParallel performs an HTTPEndpointGet for each
// input endpoint using a pool of background goroutines.
//
// You can choose the parallelism with the parallelism argument. If this
// argument is zero, or negative, we use a small default value.
//
// This function returns to the caller a channel where to read
// measurements from. The channel is closed when done.
func (mx *Measurer) HTTPEndpointGetParallel(ctx context.Context, parallelism int,
	epnts ...*HTTPEndpoint) <-chan *HTTPEndpointMeasurement {
	var (
		done   = make(chan interface{})
		input  = make(chan *HTTPEndpoint)
		output = make(chan *HTTPEndpointMeasurement)
	)
	go func() {
		defer close(input)
		for _, epnt := range epnts {
			input <- epnt
		}
	}()
	if parallelism <= 0 {
		parallelism = 4
	}
	for i := 0; i < parallelism; i++ {
		go func() {
			for epnt := range input {
				output <- mx.HTTPEndpointGet(ctx, epnt)
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
