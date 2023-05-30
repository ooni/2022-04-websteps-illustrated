package archival

//
// Saves dial and net.Conn events
//

import (
	"context"
	"net"
	"time"

	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
)

// NetworkType is the type of network we're using.
type NetworkType string

var (
	// NetworkTypeTCP indicates we're using TCP.
	NetworkTypeTCP = NetworkType("tcp")

	// NetworkTypeUDP indicates we're using UDP.
	NetworkTypeUDP = NetworkType("udp")

	// NetworkTypeQUIC indicates we're using QUIC.
	NetworkTypeQUIC = NetworkType("quic")

	// NetworkTypeDoT indicates we're using DNS-over-TLS.
	NetworkTypeDoT = NetworkType("dot")

	// NetworkTypeDoH indicates we're using DNS-over-HTTPS.
	NetworkTypeDoH = NetworkType("doh")

	// NetworkTypeDoH3 indicates we're using DNS-over-HTTP3.
	NetworkTypeDoH3 = NetworkType("doh3")

	// NetworkTypeSystem identifies the system resolver.
	NetworkTypeSystem = NetworkType("system")
)

// WrapDialer wraps a dialer to use the saver.
func (s *Saver) WrapDialer(dialer model.Dialer) model.Dialer {
	return &dialerSaver{
		Dialer: dialer,
		s:      s,
	}
}

type dialerSaver struct {
	model.Dialer
	s *Saver
}

func (d *dialerSaver) DialContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.s.dialContext(ctx, d.Dialer, network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// WrapConn wraps a conn to use the saver.
func (s *Saver) WrapConn(conn net.Conn) net.Conn {
	return &connSaver{
		Conn: conn,
		s:    s,
	}
}

type connSaver struct {
	net.Conn
	s *Saver
}

func (c *connSaver) Read(buf []byte) (int, error) {
	return c.s.read(c.Conn, buf)
}

func (c *connSaver) Write(buf []byte) (int, error) {
	return c.s.write(c.Conn, buf)
}

func (s *Saver) dialContext(ctx context.Context,
	dialer model.Dialer, network, address string) (net.Conn, error) {
	started := time.Now()
	conn, err := dialer.DialContext(ctx, network, address)
	s.appendTCPConnectEvent(&FlatNetworkEvent{
		Count:      0,
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    NetworkType(network), // "tcp" or "udp"
		Operation:  netxlite.ConnectOperation,
		RemoteAddr: address,
		Started:    started,
	})
	return conn, err
}

func (s *Saver) appendTCPConnectEvent(ev *FlatNetworkEvent) {
	if ev.Network != NetworkTypeTCP {
		// We don't care about recording UDP "connect"
		return
	}
	s.mu.Lock()
	s.trace.TCPConnect = append(s.trace.TCPConnect, ev)
	s.mu.Unlock()
}

func (s *Saver) read(conn net.Conn, buf []byte) (int, error) {
	network := conn.RemoteAddr().Network()
	remoteAddr := conn.RemoteAddr().String()
	started := time.Now()
	count, err := conn.Read(buf)
	s.appendNetworkEvent(&FlatNetworkEvent{
		Count:      int64(count),
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    NetworkType(network), // "tcp" or "udp"
		Operation:  netxlite.ReadOperation,
		RemoteAddr: remoteAddr,
		Started:    started,
	})
	return count, err
}

func (s *Saver) write(conn net.Conn, buf []byte) (int, error) {
	network := conn.RemoteAddr().Network()
	remoteAddr := conn.RemoteAddr().String()
	started := time.Now()
	count, err := conn.Write(buf)
	s.appendNetworkEvent(&FlatNetworkEvent{
		Count:      int64(count),
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    NetworkType(network), // "tcp" or "udp"
		Operation:  netxlite.WriteOperation,
		RemoteAddr: remoteAddr,
		Started:    started,
	})
	return count, err
}

func (s *Saver) appendNetworkEvent(ev *FlatNetworkEvent) {
	s.mu.Lock()
	switch ev.Operation {
	case netxlite.ReadOperation, netxlite.ReadFromOperation:
		s.nrecv += int64(ev.Count)
	case netxlite.WriteOperation, netxlite.WriteToOperation:
		s.nsent += int64(ev.Count)
	}
	if s.aggregate {
		s.maybeEmitIOMetricsLocked()
	} else {
		s.trace.Network = append(s.trace.Network, ev)
	}
	s.mu.Unlock()
}
