package netxlite

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// ErrNoDNSTransport is the error returned when you attempt to perform
// a DNS operation that requires a custom DNSTransport (e.g., DNSOverHTTPS)
// but you are using the "system" resolver instead.
var ErrNoDNSTransport = errors.New("operation requires a DNS transport")

// resolverSystem is the system resolver.
type resolverSystem struct {
	testableTimeout    time.Duration
	testableLookupHost func(ctx context.Context, domain string) ([]string, error)
}

var _ model.Resolver = &resolverSystem{}

func (r *resolverSystem) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	// This code forces adding a shorter timeout to the domain name
	// resolutions when using the system resolver. We have seen cases
	// in which such a timeout becomes too large. One such case is
	// described in https://github.com/ooni/probe/issues/1726.
	addrsch, errch := make(chan []string, 1), make(chan error, 1)
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	go func() {
		addrs, err := r.lookupHost()(ctx, hostname)
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

func (r *resolverSystem) timeout() time.Duration {
	if r.testableTimeout > 0 {
		return r.testableTimeout
	}
	return 15 * time.Second
}

func (r *resolverSystem) lookupHost() func(ctx context.Context, domain string) ([]string, error) {
	if r.testableLookupHost != nil {
		return r.testableLookupHost
	}
	return TProxy.LookupHost
}

func (r *resolverSystem) Network() string {
	return "system"
}

func (r *resolverSystem) Address() string {
	return ""
}

func (r *resolverSystem) CloseIdleConnections() {
	// nothing to do
}

func (r *resolverSystem) LookupHTTPS(
	ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	return nil, ErrNoDNSTransport
}

func (r *resolverSystem) LookupNS(
	ctx context.Context, domain string) ([]*net.NS, error) {
	// TODO(bassosimone): figure out in which context it makes sense
	// to issue this query. How is this implemented under the hood by
	// the stdlib? Is it using /etc/resolve.conf on Unix? Until we
	// known all these details, let's pretend this functionality does
	// not exist in the stdlib and focus on custom resolvers.
	return nil, ErrNoDNSTransport
}

// These vars export internal names to legacy ooni/probe-cli code.
//
// Deprecated: do not use these names in new code.
var (
	DefaultDialer        = &dialerSystem{}
	DefaultTLSHandshaker = defaultTLSHandshaker
	NewConnUTLS          = newConnUTLS
	DefaultResolver      = &resolverSystem{}
)

// These types export internal names to legacy ooni/probe-cli code.
//
// Deprecated: do not use these names in new code.
type (
	DialerResolver            = dialerResolver
	DialerLogger              = dialerLogger
	HTTPTransportLogger       = httpTransportLogger
	ErrorWrapperDialer        = dialerErrWrapper
	ErrorWrapperQUICListener  = quicListenerErrWrapper
	ErrorWrapperQUICDialer    = quicDialerErrWrapper
	ErrorWrapperResolver      = resolverErrWrapper
	ErrorWrapperTLSHandshaker = tlsHandshakerErrWrapper
	QUICListenerStdlib        = quicListenerStdlib
	QUICDialerQUICGo          = quicDialerQUICGo
	QUICDialerResolver        = quicDialerResolver
	QUICDialerLogger          = quicDialerLogger
	ResolverSystem            = resolverSystem
	ResolverLogger            = resolverLogger
	ResolverIDNA              = resolverIDNA
	TLSHandshakerConfigurable = tlsHandshakerConfigurable
	TLSHandshakerLogger       = tlsHandshakerLogger
	DialerSystem              = dialerSystem
	TLSDialerLegacy           = tlsDialer
	AddressResolver           = resolverShortCircuitIPAddr
)
