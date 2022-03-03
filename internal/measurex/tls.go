package measurex

//
// TLS
//
// This file contains code for performing TLS measurements.
//
// Note that this file is not part of probe-cli.
//

import (
	"context"
	"crypto/tls"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// TLSConnectAndHandshake connects and TLS handshakes with a TCP endpoint.
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
// Caveats:
//
// The mx.TLSHandshaker field could point to a TLS handshaker using
// the Go stdlib or one using gitlab.com/yawning/utls.git.
//
// In the latter case, the content of the ClientHello message
// will not only depend on the config field but also on the
// utls.ClientHelloID thay you're using.
//
// Returns an EndpointMeasurement.
func (mx *Measurer) TLSConnectAndHandshake(ctx context.Context,
	address string, config *tls.Config) *EndpointMeasurement {
	saver := archival.NewSaver()
	conn, _ := mx.TLSConnectAndHandshakeWithSaver(ctx, saver, address, config)
	if conn != nil {
		conn.Close()
	}
	saver.StopCollectingNetworkEvents()
	return mx.newEndpointMeasurement(NetworkTCP, address, saver.MoveOutTrace())
}

// TLSConnectAndHandshakeWithSaver is like TLSConnectAndHandshake but
// uses the given saver instead of creating a new Measurement.
//
// Caveat: the returned conn will keep saving its I/O events into
// the saver until you stop saving them explicitly.
func (mx *Measurer) TLSConnectAndHandshakeWithSaver(ctx context.Context,
	saver *archival.Saver, address string, config *tls.Config) (model.TLSConn, error) {
	conn, err := mx.TCPConnectWithSaver(ctx, saver, address)
	if err != nil {
		return nil, err
	}
	timeout := mx.TLSHandshakeTimeout
	ol := NewOperationLogger(mx.Logger, "TLSHandshake %s with sni=%s", address, config.ServerName)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	th := saver.WrapTLSHandshaker(mx.TLSHandshaker)
	tlsConn, _, err := th.Handshake(ctx, conn, config)
	ol.Stop(err)
	if err != nil {
		return nil, err
	}
	// cast safe according to the docs of netxlite's handshaker
	return tlsConn.(model.TLSConn), nil
}
