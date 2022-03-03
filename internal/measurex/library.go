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
	"github.com/lucas-clemente/quic-go"
)

// NetxliteLibrary abstracts the netxlite dependency.
type NetxliteLibrary interface {
	// NewDNSOverUDPTransport creates a new DNS-over-UDP DNS transport.
	NewDNSOverUDPTransport(dialer model.Dialer, address string) model.DNSTransport

	// NewDialerWithResolver creates a new dialer using the given logger and resolver
	NewDialerWithResolver(logger model.Logger, reso model.Resolver) model.Dialer

	// NewDialerWithoutResolver creates a new dialer not using any resolver.
	NewDialerWithoutResolver(logger model.Logger) model.Dialer

	// NewHTTP3Transport creates a new HTTPTransport using HTTP3.
	NewHTTP3Transport(logger model.Logger, dialer model.QUICDialer,
		tlsConfig *tls.Config) model.HTTPTransport

	// NewHTTPTransport creates a new HTTPTransport.
	NewHTTPTransport(logger model.Logger, dialer model.Dialer,
		tlsDialer model.TLSDialer) model.HTTPTransport

	// NewNullDialer creates a new "null" Dialer.
	NewNullDialer() model.Dialer

	// NewNullTLSDialer creates a new "null" TLSDialer.
	NewNullTLSDialer() model.TLSDialer

	// NewQUICDialerWithoutResolver creates a new QUIC dialer
	// that is not attached to any resolver.
	NewQUICDialerWithoutResolver(
		ql model.QUICListener, logger model.Logger) model.QUICDialer

	// NewQUICListener creates a new QUIC listener.
	NewQUICListener() model.QUICListener

	// NewResolverSystem creates a new "system" resolver.
	NewResolverSystem(logger model.Logger) model.Resolver

	// NewResolverSerial creates a new "serial" resolver. (Note that
	// this resolver needs to be wrapped.)
	NewResolverSerial(txp model.DNSTransport) model.Resolver

	// NewSingleUseDialer creates a new "single use" dialer.
	NewSingleUseDialer(conn net.Conn) model.Dialer

	// NewSingleUseQUICDialer creates a new "single use" QUIC dialer.
	NewSingleUseQUICDialer(sess quic.EarlySession) model.QUICDialer

	// NewSingleUseTLSDialer creates a new "single use" TLS dialer.
	NewSingleUseTLSDialer(conn model.TLSConn) model.TLSDialer

	// NewTLSHandshakerStdlib creates a new TLS handshaker using the stdlib.
	NewTLSHandshakerStdlib(logger model.Logger) model.TLSHandshaker

	// WrapResolver wraps a resolver.
	WrapResolver(logger model.Logger, reso model.Resolver) model.Resolver
}

// Library is a basic library for performing network measurements.
type Library struct {
	// logger is the logger to use.
	logger model.Logger

	// netxlite abstracts the netxlite dependency.
	netxlite NetxliteLibrary
}

// NewLibrary creates a new basic measurement library instance.
func NewLibrary(logger model.Logger, netx NetxliteLibrary) *Library {
	return &Library{
		logger:   logger,
		netxlite: netx,
	}
}

// newDialerWithSystemResolver creates a new dialer that
// saves results into the given saver and uses a system
// resolver for resolving domain names.
func (lib *Library) newDialerWithSystemResolver(saver *archival.Saver) model.Dialer {
	r := lib.NewResolverSystem(saver)
	return saver.WrapDialer(lib.netxlite.NewDialerWithResolver(lib.logger, r))
}

// NewDialerWithoutResolver is a convenience factory for creating
// a dialer that saves measurements into the saver and that is not attached
// to any resolver (hence only works when passed IP addresses).
func (lib *Library) NewDialerWithoutResolver(saver *archival.Saver) model.Dialer {
	return saver.WrapDialer(lib.netxlite.NewDialerWithoutResolver(lib.logger))
}

// NewHTTPTransportWithConn creates and wraps an HTTPTransport that
// does not dial and only uses the given conn.
func (lib *Library) NewHTTPTransportWithConn(saver *archival.Saver,
	conn net.Conn, maxBodySnapshotSize int64) model.HTTPTransport {
	return saver.WrapHTTPTransport(
		lib.netxlite.NewHTTPTransport(
			lib.logger,
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
			lib.logger,
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
			lib.logger,
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
	ql := saver.WrapQUICListener(lib.netxlite.NewQUICListener())
	return saver.WrapQUICDialer(lib.netxlite.NewQUICDialerWithoutResolver(
		ql, lib.logger,
	))
}

// NewResolverSystem creates a system resolver and then wraps
// it using the WrapResolver function.
func (lib *Library) NewResolverSystem(saver *archival.Saver) model.Resolver {
	return saver.WrapResolver(lib.netxlite.NewResolverSystem(lib.logger))
}

// NewResolverUDP is a convenience factory for creating a Resolver
// using UDP that saves measurements into the Saver.
func (lib *Library) NewResolverUDP(saver *archival.Saver, address string) model.Resolver {
	return saver.WrapResolver(
		lib.netxlite.WrapResolver(
			lib.logger,
			lib.netxlite.NewResolverSerial(
				saver.WrapDNSTransport(
					lib.netxlite.NewDNSOverUDPTransport(
						lib.newDialerWithSystemResolver(saver),
						address,
					)))))
}

// NewTLSHandshakerStdlib creates a new TLS handshaker that saves results
// into the Saver and uses the stdlib for TLS.
func (lib *Library) NewTLSHandshakerStdlib(saver *archival.Saver) model.TLSHandshaker {
	return saver.WrapTLSHandshaker(lib.netxlite.NewTLSHandshakerStdlib(lib.logger))
}
