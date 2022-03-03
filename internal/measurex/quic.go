package measurex

//
// QUIC
//
// This file contains code to measure QUIC.
//
// Note that this file is not part of ooni/probe-cli.
//

import (
	"context"
	"crypto/tls"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/lucas-clemente/quic-go"
)

// QUICHandshake connects and TLS handshakes with a QUIC endpoint.
//
// Arguments:
//
// - ctx is the context allowing to timeout the whole operation;
//
// - address is the endpoint address (e.g., "1.1.1.1:443");
//
// - config contains the TLS config (see below).
//
// You MUST set the following config fields:
//
// - ServerName to the desired SNI or InsecureSkipVerify to
// skip the certificate name verification;
//
// - RootCAs to nextlite.NewDefaultCertPool() output;
//
// - NextProtos to the desired ALPN ([]string{"h2", "http/1.1"} for
// HTTPS and []string{"dot"} for DNS-over-TLS).
//
// Returns an EndpointMeasurement.
func (mx *Measurer) QUICHandshake(ctx context.Context, address string,
	config *tls.Config) *EndpointMeasurement {
	saver := archival.NewSaver()
	sess, _ := mx.QUICHandshakeWithSaver(ctx, saver, address, config)
	if sess != nil {
		// TODO(bassosimone): close session with correct message
		sess.CloseWithError(0, "")
	}
	saver.StopCollectingNetworkEvents()
	return mx.newEndpointMeasurement(NetworkQUIC, address, saver.MoveOutTrace())
}

// QUICHandshakeWithSaver is like QUICHandshake but uses the given
// saver to store events rather than creating a temporary one and
// use it to generate a new Measurement.
//
// Caveat: the returned conn will keep saving its I/O events into
// the saver until you stop saving them explicitly.
func (mx *Measurer) QUICHandshakeWithSaver(ctx context.Context, saver *archival.Saver,
	address string, config *tls.Config) (quic.EarlySession, error) {
	timeout := mx.QUICHandshakeTimeout
	ol := NewOperationLogger(mx.Logger, "QUICHandshake %s with sni=%s", address, config.ServerName)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	qd := mx.Library.NewQUICDialerWithoutResolver(saver)
	defer qd.CloseIdleConnections()
	sess, err := qd.DialContext(ctx, "udp", address, config, &quic.Config{})
	ol.Stop(err)
	return sess, err
}
