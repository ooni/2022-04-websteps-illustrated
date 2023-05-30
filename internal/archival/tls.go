package archival

//
// Saves TLS events
//

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
)

// WrapTLSHandshaker wraps a TLS handshaker to use the saver.
func (s *Saver) WrapTLSHandshaker(thx model.TLSHandshaker) model.TLSHandshaker {
	return &tlsHandshakerSaver{
		TLSHandshaker: thx,
		s:             s,
	}
}

type tlsHandshakerSaver struct {
	model.TLSHandshaker
	s *Saver
}

func (thx *tlsHandshakerSaver) Handshake(ctx context.Context,
	conn net.Conn, config *tls.Config) (net.Conn, tls.ConnectionState, error) {
	return thx.s.tlsHandshake(ctx, thx.TLSHandshaker, conn, config)
}

func (s *Saver) tlsHandshake(ctx context.Context, thx model.TLSHandshaker,
	conn net.Conn, config *tls.Config) (net.Conn, tls.ConnectionState, error) {
	network := conn.RemoteAddr().Network()
	remoteAddr := conn.RemoteAddr().String()
	started := time.Now()
	tconn, state, err := thx.Handshake(ctx, conn, config)
	// Implementation note: state is an empty ConnectionState on failure
	// so it's safe to access its fields also in that case
	s.appendQUICTLSHandshake(&FlatQUICTLSHandshakeEvent{
		ALPN:            config.NextProtos,
		CipherSuite:     netxlite.TLSCipherSuiteString(state.CipherSuite),
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		NegotiatedProto: state.NegotiatedProtocol,
		Network:         NetworkType(network), // we expect this to be "tcp"
		PeerCerts:       s.tlsPeerCerts(err, &state),
		RemoteAddr:      remoteAddr,
		SNI:             config.ServerName,
		SkipVerify:      config.InsecureSkipVerify,
		Started:         started,
		TLSVersion:      netxlite.TLSVersionString(state.Version),
	})
	return tconn, state, err
}

func (s *Saver) tlsPeerCerts(err error, state *tls.ConnectionState) (out [][]byte) {
	var x509HostnameError x509.HostnameError
	if errors.As(err, &x509HostnameError) {
		// Test case: https://wrong.host.badssl.com/
		return [][]byte{x509HostnameError.Certificate.Raw}
	}
	var x509UnknownAuthorityError x509.UnknownAuthorityError
	if errors.As(err, &x509UnknownAuthorityError) {
		// Test case: https://self-signed.badssl.com/. This error has
		// never been among the ones returned by MK.
		return [][]byte{x509UnknownAuthorityError.Cert.Raw}
	}
	var x509CertificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &x509CertificateInvalidError) {
		// Test case: https://expired.badssl.com/
		return [][]byte{x509CertificateInvalidError.Cert.Raw}
	}
	for _, cert := range state.PeerCertificates {
		out = append(out, cert.Raw)
	}
	return
}
