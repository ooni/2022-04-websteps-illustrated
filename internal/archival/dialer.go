package archival

//
// Saves dial and net.Conn events
//

import (
	"context"
	"net"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
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
	s.appendNetworkEvent(&FlatNetworkEvent{
		Count:      0,
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    network,
		Operation:  netxlite.ConnectOperation,
		RemoteAddr: address,
		Started:    started,
	})
	return conn, err
}

func (s *Saver) read(conn net.Conn, buf []byte) (int, error) {
	network := conn.RemoteAddr().Network()
	remoteAddr := conn.RemoteAddr().String()
	started := time.Now()
	count, err := conn.Read(buf)
	s.appendNetworkEvent(&FlatNetworkEvent{
		Count:      count,
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    network,
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
		Count:      count,
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    network,
		Operation:  netxlite.WriteOperation,
		RemoteAddr: remoteAddr,
		Started:    started,
	})
	return count, err
}

func (s *Saver) appendNetworkEvent(ev *FlatNetworkEvent) {
	s.mu.Lock()
	if !s.dcne {
		s.trace.Network = append(s.trace.Network, ev)
	}
	s.mu.Unlock()
}
