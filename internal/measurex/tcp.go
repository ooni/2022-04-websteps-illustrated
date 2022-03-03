package measurex

//
// TCP
//
// This file contains code to perform TCP measurements.
//
// Note that this file is not part of probe-cli.
//

import (
	"context"
	"net"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
)

// TCPConnect establishes a connection with a TCP endpoint.
//
// Arguments:
//
// - ctx is the context allowing to timeout the connect;
//
// - address is the TCP endpoint address (e.g., "8.8.4.4:443").
//
// Returns an EndpointMeasurement.
func (mx *Measurer) TCPConnect(ctx context.Context, address string) *EndpointMeasurement {
	saver := archival.NewSaver()
	conn, _ := mx.TCPConnectWithSaver(ctx, saver, address)
	if conn != nil {
		conn.Close()
	}
	return mx.newEndpointMeasurement(NetworkTCP, address, saver.MoveOutTrace())
}

// TCPConnectWithSaver is like TCPConnect but does not create a new measurement,
// rather it just stores the events inside of the given saver.
func (mx *Measurer) TCPConnectWithSaver(ctx context.Context,
	saver *archival.Saver, address string) (net.Conn, error) {
	timeout := mx.TCPconnectTimeout
	ol := NewOperationLogger(mx.Logger, "TCPConnect %s", address)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := mx.Library.NewDialerWithoutResolver(saver)
	defer d.CloseIdleConnections()
	conn, err := d.DialContext(ctx, "tcp", address)
	ol.Stop(err)
	return conn, err
}
