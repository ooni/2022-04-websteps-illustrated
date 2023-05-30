package archival

//
// Saves QUIC events.
//

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
)

// WrapUDPListener wraps a UDPListener to use the saver.
func (s *Saver) WrapUDPListener(ql model.UDPListener) model.UDPListener {
	return &quicListenerSaver{
		UDPListener: ql,
		s:           s,
	}
}

// WrapQUICDialer wraps a QUICDialer to use the saver.
func (s *Saver) WrapQUICDialer(qd model.QUICDialer) model.QUICDialer {
	return &quicDialerSaver{
		QUICDialer: qd,
		s:          s,
	}
}

type quicListenerSaver struct {
	model.UDPListener
	s *Saver
}

func (ql *quicListenerSaver) Listen(addr *net.UDPAddr) (model.UDPLikeConn, error) {
	pconn, err := ql.UDPListener.Listen(addr)
	if err != nil {
		return nil, err
	}
	return &udpLikeConnSaver{
		UDPLikeConn: pconn,
		s:           ql.s,
	}, nil
}

type udpLikeConnSaver struct {
	model.UDPLikeConn
	s *Saver
}

func (c *udpLikeConnSaver) WriteTo(buf []byte, addr net.Addr) (int, error) {
	return c.s.writeTo(c.UDPLikeConn, buf, addr)
}

func (c *udpLikeConnSaver) ReadFrom(buf []byte) (int, net.Addr, error) {
	return c.s.readFrom(c.UDPLikeConn, buf)
}

func (s *Saver) writeTo(pconn model.UDPLikeConn, buf []byte, addr net.Addr) (int, error) {
	started := time.Now()
	count, err := pconn.WriteTo(buf, addr)
	s.appendNetworkEvent(&FlatNetworkEvent{
		Count:      int64(count),
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    NetworkType(addr.Network()), // "udp"
		Operation:  netxlite.WriteToOperation,
		RemoteAddr: addr.String(),
		Started:    started,
	})
	return count, err
}

func (s *Saver) readFrom(pconn model.UDPLikeConn, buf []byte) (int, net.Addr, error) {
	started := time.Now()
	count, addr, err := pconn.ReadFrom(buf)
	s.appendNetworkEvent(&FlatNetworkEvent{
		Count:      int64(count),
		Failure:    NewFlatFailure(err),
		Finished:   time.Now(),
		Network:    NetworkTypeUDP, // must be always set even on failure
		Operation:  netxlite.ReadFromOperation,
		RemoteAddr: s.safeAddrString(addr),
		Started:    started,
	})
	return count, addr, err
}

func (s *Saver) safeAddrString(addr net.Addr) (out string) {
	if addr != nil {
		out = addr.String()
	}
	return
}

type quicDialerSaver struct {
	model.QUICDialer
	s *Saver
}

func (qd *quicDialerSaver) DialContext(ctx context.Context, network, address string,
	tlsConfig *tls.Config, quicConfig *quic.Config) (quic.EarlySession, error) {
	return qd.s.quicDialContext(
		ctx, qd.QUICDialer, network, address, tlsConfig, quicConfig)
}

func (s *Saver) quicDialContext(ctx context.Context, dialer model.QUICDialer,
	network, address string, tlsConfig *tls.Config,
	quicConfig *quic.Config) (quic.EarlySession, error) {
	started := time.Now()
	var state tls.ConnectionState
	sess, err := dialer.DialContext(ctx, network, address, tlsConfig, quicConfig)
	if err == nil {
		select {
		case <-sess.HandshakeComplete().Done():
			state = sess.ConnectionState().TLS.ConnectionState
		case <-ctx.Done():
			sess, err = nil, ctx.Err()
		}
	}
	s.appendQUICTLSHandshake(&FlatQUICTLSHandshakeEvent{
		ALPN:            tlsConfig.NextProtos,
		CipherSuite:     netxlite.TLSCipherSuiteString(state.CipherSuite),
		Failure:         NewFlatFailure(err),
		Finished:        time.Now(),
		NegotiatedProto: state.NegotiatedProtocol,
		Network:         NetworkTypeQUIC,
		PeerCerts:       s.tlsPeerCerts(err, &state),
		RemoteAddr:      address,
		SNI:             tlsConfig.ServerName,
		SkipVerify:      tlsConfig.InsecureSkipVerify,
		Started:         started,
		TLSVersion:      netxlite.TLSVersionString(state.Version),
	})
	return sess, err
}

func (s *Saver) appendQUICTLSHandshake(ev *FlatQUICTLSHandshakeEvent) {
	s.mu.Lock()
	s.trace.QUICTLSHandshake = append(s.trace.QUICTLSHandshake, ev)
	s.mu.Unlock()
}
