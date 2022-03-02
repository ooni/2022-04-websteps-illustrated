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

// DialContext dials with the given dialer with the given arguments
// and stores the dial result inside of this saver.
func (s *Saver) DialContext(ctx context.Context,
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

// Read reads from the given conn and stores the results in the saver.
func (s *Saver) Read(conn net.Conn, buf []byte) (int, error) {
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

// Write writes to the given conn and stores the results into the saver.
func (s *Saver) Write(conn net.Conn, buf []byte) (int, error) {
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
	s.trace.Network = append(s.trace.Network, ev)
	s.mu.Unlock()
}
