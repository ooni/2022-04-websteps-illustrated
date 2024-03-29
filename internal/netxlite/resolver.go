package netxlite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"golang.org/x/net/idna"
)

// NewResolverStdlib creates a new Resolver by combining WrapResolver
// with a a DNSSystemResolver using a DNSSystemTransport.
func NewResolverStdlib(logger model.DebugLogger) model.Resolver {
	return WrapResolver(logger, NewDNSSystemResolver(NewDNSSystemTransport()))
}

// NewResolverUDP creates a new Resolver using DNS-over-UDP.
//
// Arguments:
//
// - logger is the logger to use
//
// - dialer is the dialer to create and connect UDP conns
//
// - address is the server address (e.g., 1.1.1.1:53)
func NewResolverUDP(logger model.DebugLogger, dialer model.Dialer, address string) model.Resolver {
	return WrapResolver(logger, NewSerialResolver(
		NewDNSOverUDPTransport(dialer, address),
	))
}

// WrapResolver creates a new resolver that wraps an
// existing resolver to add these properties:
//
// 1. handles IDNA;
//
// 2. performs logging;
//
// 3. short-circuits IP addresses like getaddrinfo does (i.e.,
// resolving "1.1.1.1" yields []string{"1.1.1.1"};
//
// 4. wraps errors;
//
// 5. enforces reasonable timeouts (
// see https://github.com/ooni/probe/issues/1726).
//
// This is a low-level factory. Use only if out of alternatives.
func WrapResolver(logger model.DebugLogger, resolver model.Resolver) model.Resolver {
	return &resolverIDNA{
		Resolver: &resolverLogger{
			Resolver: &resolverShortCircuitIPAddr{
				Resolver: &resolverErrWrapper{
					Resolver: resolver,
				},
			},
			Logger: logger,
		},
	}
}

// resolverLogger is a resolver that emits events
type resolverLogger struct {
	Resolver model.Resolver
	Logger   model.DebugLogger
}

var _ model.Resolver = &resolverLogger{}

func (r *resolverLogger) CloseIdleConnections() {
	r.Resolver.CloseIdleConnections()
}

func (r *resolverLogger) Network() string {
	return r.Resolver.Network()
}

func (r *resolverLogger) Address() string {
	return r.Resolver.Address()
}

func (r *resolverLogger) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	prefix := fmt.Sprintf("resolve[A,AAAA] %s with %s (%s)", hostname, r.Network(), r.Address())
	logcat.Tracef("%s...", prefix)
	start := time.Now()
	addrs, err := r.Resolver.LookupHost(ctx, hostname)
	elapsed := time.Since(start)
	if err != nil {
		logcat.Tracef("%s... %s in %s", prefix, err, elapsed)
		return nil, err
	}
	logcat.Tracef("%s... %+v in %s", prefix, addrs, elapsed)
	return addrs, nil
}

func (r *resolverLogger) LookupHTTPS(
	ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	prefix := fmt.Sprintf("resolve[HTTPS] %s with %s (%s)", domain, r.Network(), r.Address())
	logcat.Tracef("%s...", prefix)
	start := time.Now()
	https, err := r.Resolver.LookupHTTPS(ctx, domain)
	elapsed := time.Since(start)
	if err != nil {
		logcat.Tracef("%s... %s in %s", prefix, err, elapsed)
		return nil, err
	}
	alpn := https.ALPN
	a := https.IPv4
	aaaa := https.IPv6
	logcat.Tracef("%s... %+v %+v %+v in %s", prefix, alpn, a, aaaa, elapsed)
	return https, nil
}

func (r *resolverLogger) LookupNS(
	ctx context.Context, domain string) ([]*net.NS, error) {
	prefix := fmt.Sprintf("resolve[NS] %s with %s (%s)", domain, r.Network(), r.Address())
	logcat.Tracef("%s...", prefix)
	start := time.Now()
	ns, err := r.Resolver.LookupNS(ctx, domain)
	elapsed := time.Since(start)
	if err != nil {
		logcat.Tracef("%s... %s in %s", prefix, err, elapsed)
		return nil, err
	}
	logcat.Tracef("%s... %+v in %s", prefix, ns, elapsed)
	return ns, nil
}

func (r *resolverLogger) LookupPTR(
	ctx context.Context, domain string) ([]string, error) {
	prefix := fmt.Sprintf("resolve[PTR] %s with %s (%s)", domain, r.Network(), r.Address())
	logcat.Tracef("%s...", prefix)
	start := time.Now()
	domains, err := r.Resolver.LookupPTR(ctx, domain)
	elapsed := time.Since(start)
	if err != nil {
		logcat.Tracef("%s... %s in %s", prefix, err, elapsed)
		return nil, err
	}
	logcat.Tracef("%s... %+v in %s", prefix, domains, elapsed)
	return domains, nil
}

// resolverIDNA supports resolving Internationalized Domain Names.
//
// See RFC3492 for more information.
type resolverIDNA struct {
	Resolver model.Resolver
}

func (r *resolverIDNA) Network() string {
	return r.Resolver.Network()
}

func (r *resolverIDNA) Address() string {
	return r.Resolver.Address()
}

func (r *resolverIDNA) CloseIdleConnections() {
	r.Resolver.CloseIdleConnections()
}

func (r *resolverIDNA) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	host, err := idna.ToASCII(hostname)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupHost(ctx, host)
}

func (r *resolverIDNA) LookupHTTPS(
	ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	host, err := idna.ToASCII(domain)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupHTTPS(ctx, host)
}

func (r *resolverIDNA) LookupNS(
	ctx context.Context, domain string) ([]*net.NS, error) {
	host, err := idna.ToASCII(domain)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupNS(ctx, host)
}

func (r *resolverIDNA) LookupPTR(
	ctx context.Context, domain string) ([]string, error) {
	host, err := idna.ToASCII(domain)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupPTR(ctx, host)
}

// resolverShortCircuitIPAddr recognizes when the input hostname is an
// IP address and returns it immediately to the caller.
type resolverShortCircuitIPAddr struct {
	Resolver model.Resolver
}

func (r *resolverShortCircuitIPAddr) Network() string {
	return r.Resolver.Network()
}

func (r *resolverShortCircuitIPAddr) Address() string {
	return r.Resolver.Address()
}

func (r *resolverShortCircuitIPAddr) CloseIdleConnections() {
	r.Resolver.CloseIdleConnections()
}

func (r *resolverShortCircuitIPAddr) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	if net.ParseIP(hostname) != nil {
		return []string{hostname}, nil
	}
	return r.Resolver.LookupHost(ctx, hostname)
}

// IsIPv6 returns true if the given candidate is a valid IP address
// representation and such representation is IPv6.
func IsIPv6(candidate string) (bool, error) {
	if net.ParseIP(candidate) == nil {
		return false, ErrInvalidIP
	}
	return isIPv6(candidate), nil
}

// isIPv6 returns true if the given IP address is IPv6.
func isIPv6(candidate string) bool {
	// This check for identifying IPv6 is discussed
	// at https://stackoverflow.com/questions/22751035
	// and seems good-enough for our purposes.
	return strings.Contains(candidate, ":")
}

func (r *resolverShortCircuitIPAddr) LookupHTTPS(ctx context.Context, hostname string) (*model.HTTPSSvc, error) {
	if net.ParseIP(hostname) != nil {
		https := &model.HTTPSSvc{}
		if isIPv6(hostname) {
			https.IPv6 = append(https.IPv6, hostname)
		} else {
			https.IPv4 = append(https.IPv4, hostname)
		}
		return https, nil
	}
	return r.Resolver.LookupHTTPS(ctx, hostname)
}

// ErrDNSIPAddress indicates that you passed an IP address to a DNS
// function that only works with domain names.
var ErrDNSIPAddress = errors.New("ooresolver: expected domain, found IP address")

func (r *resolverShortCircuitIPAddr) LookupNS(
	ctx context.Context, hostname string) ([]*net.NS, error) {
	if net.ParseIP(hostname) != nil {
		return nil, ErrDNSIPAddress
	}
	return r.Resolver.LookupNS(ctx, hostname)
}

func (r *resolverShortCircuitIPAddr) LookupPTR(
	ctx context.Context, domain string) ([]string, error) {
	return r.Resolver.LookupPTR(ctx, domain)
}

// ErrNoResolver is the type of error returned by "without resolver"
// dialer when asked to dial for and endpoint containing a domain name,
// since they can only dial for endpoints containing IP addresses.
var ErrNoResolver = errors.New("no configured resolver")

// nullResolver is a resolver that is not capable of resolving
// domain names to IP addresses and always returns ErrNoResolver.
type nullResolver struct{}

func (r *nullResolver) LookupHost(ctx context.Context, hostname string) (addrs []string, err error) {
	return nil, ErrNoResolver
}

func (r *nullResolver) Network() string {
	return "null"
}

func (r *nullResolver) Address() string {
	return ""
}

func (r *nullResolver) CloseIdleConnections() {
	// nothing to do
}

func (r *nullResolver) LookupHTTPS(
	ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	return nil, ErrNoResolver
}

func (r *nullResolver) LookupNS(
	ctx context.Context, domain string) ([]*net.NS, error) {
	return nil, ErrNoResolver
}

func (r *nullResolver) LookupPTR(
	ctx context.Context, domain string) ([]string, error) {
	return nil, ErrNoResolver
}

// resolverErrWrapper is a Resolver that knows about wrapping errors.
type resolverErrWrapper struct {
	Resolver model.Resolver
}

var _ model.Resolver = &resolverErrWrapper{}

func (r *resolverErrWrapper) Network() string {
	return r.Resolver.Network()
}

func (r *resolverErrWrapper) Address() string {
	return r.Resolver.Address()
}

func (r *resolverErrWrapper) CloseIdleConnections() {
	r.Resolver.CloseIdleConnections()
}

func (r *resolverErrWrapper) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	addrs, err := r.Resolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, NewErrWrapper(ClassifyResolverError, ResolveOperation, err)
	}
	return addrs, nil
}

func (r *resolverErrWrapper) LookupHTTPS(
	ctx context.Context, domain string) (*model.HTTPSSvc, error) {
	out, err := r.Resolver.LookupHTTPS(ctx, domain)
	if err != nil {
		return nil, NewErrWrapper(ClassifyResolverError, ResolveOperation, err)
	}
	return out, nil
}

func (r *resolverErrWrapper) LookupNS(
	ctx context.Context, domain string) ([]*net.NS, error) {
	out, err := r.Resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, NewErrWrapper(ClassifyResolverError, ResolveOperation, err)
	}
	return out, nil
}

func (r *resolverErrWrapper) LookupPTR(
	ctx context.Context, domain string) ([]string, error) {
	out, err := r.Resolver.LookupPTR(ctx, domain)
	if err != nil {
		return nil, NewErrWrapper(ClassifyResolverError, ResolveOperation, err)
	}
	return out, nil
}
