package measurex

//
// This file contains low-level library functionality to construct
// measurable netx interfaces (e.g., Dialer, HTTPTransport).
//

import (
	"crypto/tls"
	"net"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/lucas-clemente/quic-go"
)

/*
	TODO(bassosimone): continue refactoring the code to use logcat rather
	than the model.Logger. I did not do that for netxlite because I am
	aware that I'll need to merge this code back into probe-cli. So, I'd
	rather finish this piece of refactoring after the merge.
*/

// NetxliteLibrary abstracts the netxlite dependency.
type NetxliteLibrary interface {
	// NewDNSOverUDPTransport creates a new DNS-over-UDP DNS transport.
	NewDNSOverUDPTransport(dialer model.Dialer, address string) model.DNSTransport

	// NewDNSOverHTTPSTransport creates a new DNS-over-HTTPS DNS transport. The
	// network argument should be one of "doh" and "doh3".
	NewDNSOverHTTPSTransport(clnt model.HTTPClient, network, address string) model.DNSTransport

	// NewDNSSystemResolver creates a DNS resolver using the system resolver.
	NewDNSSystemResolver(txp model.DNSTransport) model.Resolver

	// NewDNSSystemTransport creates a DNS transport using the system resolver.
	NewDNSSystemTransport() model.DNSTransport

	// NewDialerWithResolver creates a new dialer using the given resolver
	NewDialerWithResolver(reso model.Resolver) model.Dialer

	// NewDialerWithoutResolver creates a new dialer not using any resolver.
	NewDialerWithoutResolver() model.Dialer

	// NewHTTP3Transport creates a new HTTPTransport using HTTP3.
	NewHTTP3Transport(dialer model.QUICDialer, tlsConfig *tls.Config) model.HTTPTransport

	// NewHTTPTransport creates a new HTTPTransport.
	NewHTTPTransport(dialer model.Dialer, tlsDialer model.TLSDialer) model.HTTPTransport

	// NewNullDialer creates a new "null" Dialer.
	NewNullDialer() model.Dialer

	// NewNullTLSDialer creates a new "null" TLSDialer.
	NewNullTLSDialer() model.TLSDialer

	// NewQUICDialerWithoutResolver creates a new QUIC dialer
	// that is not attached to any resolver.
	NewQUICDialerWithoutResolver(ql model.UDPListener) model.QUICDialer

	// NewUDPListener creates a new UDP listener.
	NewUDPListener() model.UDPListener

	// NewUnwrappedParallelResolver creates a new "parallel" resolver. (Note that
	// this resolver needs to be wrapped.)
	NewUnwrappedParallelResolver(txp model.DNSTransport) model.Resolver

	// NewSingleUseDialer creates a new "single use" dialer.
	NewSingleUseDialer(conn net.Conn) model.Dialer

	// NewSingleUseQUICDialer creates a new "single use" QUIC dialer.
	NewSingleUseQUICDialer(sess quic.EarlySession) model.QUICDialer

	// NewSingleUseTLSDialer creates a new "single use" TLS dialer.
	NewSingleUseTLSDialer(conn model.TLSConn) model.TLSDialer

	// NewTLSHandshakerStdlib creates a new TLS handshaker using the stdlib.
	NewTLSHandshakerStdlib() model.TLSHandshaker

	// WrapHTTPClient wraps an HTTP client.
	WrapHTTPClient(clnt model.HTTPClient) model.HTTPClient

	// WrapResolver wraps a resolver.
	WrapResolver(reso model.Resolver) model.Resolver
}

// Library is a basic library for performing network measurements.
type Library struct {
	// netxlite abstracts the netxlite dependency.
	netxlite NetxliteLibrary
}

// NewLibrary creates a new basic measurement library instance using
// a custom implementation of the nextlite library.
func NewLibrary(netx NetxliteLibrary) *Library {
	return &Library{
		netxlite: netx,
	}
}

// NewDefaultLibrary creates a Library that uses netxlite.
func NewDefaultLibrary() *Library {
	return NewLibrary(&netxliteLibrary{})
}

// newDialerWithSystemResolver creates a new dialer that
// saves results into the given saver and uses a system
// resolver for resolving domain names.
func (lib *Library) newDialerWithSystemResolver(saver *archival.Saver) model.Dialer {
	r := lib.NewResolverSystem(saver)
	return saver.WrapDialer(lib.netxlite.NewDialerWithResolver(r))
}

// NewDialerWithoutResolver is a convenience factory for creating
// a dialer that saves measurements into the saver and that is not attached
// to any resolver (hence only works when passed IP addresses).
func (lib *Library) NewDialerWithoutResolver(saver *archival.Saver) model.Dialer {
	return saver.WrapDialer(lib.netxlite.NewDialerWithoutResolver())
}

// NewHTTPTransportWithConn creates and wraps an HTTPTransport that
// does not dial and only uses the given conn.
func (lib *Library) NewHTTPTransportWithConn(saver *archival.Saver,
	conn net.Conn, maxBodySnapshotSize int64) model.HTTPTransport {
	return saver.WrapHTTPTransport(
		lib.netxlite.NewHTTPTransport(
			lib.netxlite.NewSingleUseDialer(conn),
			lib.netxlite.NewNullTLSDialer()),
		maxBodySnapshotSize,
	)
}

// NewHTTPTransportWithTLSConn creates and wraps an HTTPTransport that
// does not dial and only uses the given conn.
func (lib *Library) NewHTTPTransportWithTLSConn(saver *archival.Saver,
	conn model.TLSConn, maxBodySnapshotSize int64) model.HTTPTransport {
	return saver.WrapHTTPTransport(
		lib.netxlite.NewHTTPTransport(
			lib.netxlite.NewNullDialer(),
			lib.netxlite.NewSingleUseTLSDialer(conn)),
		maxBodySnapshotSize,
	)
}

// NewHTTPTransportWithQUICSess creates and wraps an HTTPTransport that
// does not dial and only uses the given QUIC session.
func (lib *Library) NewHTTPTransportWithQUICSess(saver *archival.Saver,
	sess quic.EarlySession, maxBodySnapshotSize int64) model.HTTPTransport {
	return saver.WrapHTTPTransport(
		lib.netxlite.NewHTTP3Transport(
			lib.netxlite.NewSingleUseQUICDialer(sess),
			&tls.Config{},
		), maxBodySnapshotSize,
	)
}

// NewQUICDialerWithoutResolver creates a new QUICDialer that is not
// attached to any resolver. This means that every attempt to dial any
// address containing a domain name will fail. This QUICDialer will
// save any event into the Saver. Any QUICConn created by it will
// likewise save any event into the Saver.
func (lib *Library) NewQUICDialerWithoutResolver(saver *archival.Saver) model.QUICDialer {
	ql := saver.WrapUDPListener(lib.netxlite.NewUDPListener())
	return saver.WrapQUICDialer(lib.netxlite.NewQUICDialerWithoutResolver(ql))
}

// NewResolverSystem creates a system resolver and then wraps
// it using the WrapResolver function.
func (lib *Library) NewResolverSystem(saver *archival.Saver) model.Resolver {
	return saver.WrapResolver(
		lib.netxlite.WrapResolver(
			lib.netxlite.NewDNSSystemResolver(
				saver.WrapDNSTransport(
					lib.netxlite.NewDNSSystemTransport(),
				))))
}

// NewResolverUDP is a convenience factory for creating a Resolver
// using UDP that saves measurements into the Saver.
func (lib *Library) NewResolverUDP(saver *archival.Saver, address string) model.Resolver {
	return saver.WrapResolver(
		lib.netxlite.WrapResolver(
			lib.netxlite.NewUnwrappedParallelResolver(
				saver.WrapDNSTransport(
					lib.netxlite.NewDNSOverUDPTransport(
						lib.newDialerWithSystemResolver(saver),
						address,
					)))))
}

// NewResolverDoH is a convenience factory for creating a Resolver
// using DNS-over-HTTPS that saves measurements into the Saver.
//
// Note that we'll not save HTTP related events (such as connecting,
// or handshaking) when issuing queries because the lifecycle of
// the HTTP client is much larger than the one of the saver.
//
// The network argument should one of "doh" and "doh3". The former
// uses DNS-over-HTTPS and the latter DNS-over-HTTP3.
func (lib *Library) NewResolverDoH(saver *archival.Saver,
	clnt model.HTTPClient, network, address string) model.Resolver {
	return saver.WrapResolver(
		lib.netxlite.WrapResolver(
			lib.netxlite.NewUnwrappedParallelResolver(
				saver.WrapDNSTransport(
					lib.netxlite.NewDNSOverHTTPSTransport(
						clnt,
						network,
						address,
					)))))
}

// NewTLSHandshakerStdlib creates a new TLS handshaker that uses the
// Go standard library by invoking the underlying netxlite library.
func (lib *Library) NewTLSHandshakerStdlib() model.TLSHandshaker {
	return lib.netxlite.NewTLSHandshakerStdlib()
}

// WrapHTTPClient wraps an HTTP client using the underlying netxlite library.
func (lib *Library) WrapHTTPClient(clnt model.HTTPClient) model.HTTPClient {
	return lib.netxlite.WrapHTTPClient(clnt)
}

// netxliteLibrary is the default NetxliteLibrary implementation.
type netxliteLibrary struct{}

func (nl *netxliteLibrary) NewDNSOverUDPTransport(
	dialer model.Dialer, address string) model.DNSTransport {
	return netxlite.NewDNSOverUDPTransport(dialer, address)
}

func (nl *netxliteLibrary) NewDNSOverHTTPSTransport(
	clnt model.HTTPClient, network, address string) model.DNSTransport {
	return &netxlite.DNSOverHTTPSTransport{
		Client:       clnt,
		URL:          address,
		HostOverride: "",
		Protocol:     network,
	}
}

func (nl *netxliteLibrary) NewDNSSystemResolver(txp model.DNSTransport) model.Resolver {
	return netxlite.NewDNSSystemResolver(txp)
}

func (nl *netxliteLibrary) NewDNSSystemTransport() model.DNSTransport {
	return netxlite.NewDNSSystemTransport()
}

func (nl *netxliteLibrary) NewDialerWithResolver(reso model.Resolver) model.Dialer {
	return netxlite.NewDialerWithResolver(model.DiscardLogger, reso)
}

func (nl *netxliteLibrary) NewDialerWithoutResolver() model.Dialer {
	return netxlite.NewDialerWithoutResolver(model.DiscardLogger)
}

func (nl *netxliteLibrary) NewHTTP3Transport(dialer model.QUICDialer,
	tlsConfig *tls.Config) model.HTTPTransport {
	return netxlite.NewHTTP3Transport(model.DiscardLogger, dialer, tlsConfig)
}

func (nl *netxliteLibrary) NewHTTPTransport(dialer model.Dialer,
	tlsDialer model.TLSDialer) model.HTTPTransport {
	return netxlite.NewHTTPTransport(model.DiscardLogger, dialer, tlsDialer)
}

func (nl *netxliteLibrary) NewNullDialer() model.Dialer {
	return netxlite.NewNullDialer()
}

func (nl *netxliteLibrary) NewNullTLSDialer() model.TLSDialer {
	return netxlite.NewNullTLSDialer()
}

func (nl *netxliteLibrary) NewQUICDialerWithoutResolver(ql model.UDPListener) model.QUICDialer {
	return netxlite.NewQUICDialerWithoutResolver(ql, model.DiscardLogger)
}

func (nl *netxliteLibrary) NewUDPListener() model.UDPListener {
	return netxlite.NewUDPListener()
}

func (nl *netxliteLibrary) NewUnwrappedParallelResolver(txp model.DNSTransport) model.Resolver {
	return netxlite.NewUnwrappedParallelResolver(txp)
}

func (nl *netxliteLibrary) NewSingleUseDialer(conn net.Conn) model.Dialer {
	return netxlite.NewSingleUseDialer(conn)
}

func (nl *netxliteLibrary) NewSingleUseQUICDialer(sess quic.EarlySession) model.QUICDialer {
	return netxlite.NewSingleUseQUICDialer(sess)
}

func (nl *netxliteLibrary) NewSingleUseTLSDialer(conn model.TLSConn) model.TLSDialer {
	return netxlite.NewSingleUseTLSDialer(conn)
}

func (nl *netxliteLibrary) NewTLSHandshakerStdlib() model.TLSHandshaker {
	return netxlite.NewTLSHandshakerStdlib(model.DiscardLogger)
}

func (nl *netxliteLibrary) WrapHTTPClient(clnt model.HTTPClient) model.HTTPClient {
	return netxlite.WrapHTTPClient(clnt)
}

func (nl *netxliteLibrary) WrapResolver(reso model.Resolver) model.Resolver {
	return netxlite.WrapResolver(model.DiscardLogger, reso)
}
