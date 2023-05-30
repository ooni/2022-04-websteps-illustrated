package netxlite

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
)

// NewUDPListener creates a new UDPListener using the standard
// library to create listening UDP sockets.
func NewUDPListener() model.UDPListener {
	return &quicListenerErrWrapper{&quicListenerStdlib{}}
}

// quicListenerStdlib is a UDPListener using the standard library.
type quicListenerStdlib struct{}

var _ model.UDPListener = &quicListenerStdlib{}

// Listen implements UDPListener.Listen.
func (qls *quicListenerStdlib) Listen(addr *net.UDPAddr) (model.UDPLikeConn, error) {
	return TProxy.ListenUDP("udp", addr)
}

// NewQUICDialerWithResolver returns a QUICDialer using the given
// UDPListener to create listening connections and the given Resolver
// to resolve domain names (if needed).
//
// Properties of the dialer:
//
// 1. logs events using the given logger;
//
// 2. resolves domain names using the givern resolver;
//
// 3. when using a resolver, _may_ attempt multiple dials
// in parallel (happy eyeballs) and _may_ return an aggregate
// error to the caller;
//
// 4. wraps errors;
//
// 5. has a configured connect timeout;
//
// 6. if a dialer wraps a resolver, the dialer will forward
// the CloseIdleConnection call to its resolver (which is
// instrumental to manage a DoH resolver connections properly).
func NewQUICDialerWithResolver(listener model.UDPListener,
	logger model.DebugLogger, resolver model.Resolver) model.QUICDialer {
	return &quicDialerLogger{
		Dialer: &quicDialerResolver{
			Dialer: &quicDialerLogger{
				Dialer: &quicDialerErrWrapper{
					QUICDialer: &quicDialerQUICGo{
						UDPListener: listener,
					}},
				Logger:          logger,
				operationSuffix: "_address",
			},
			Resolver: resolver,
		},
		Logger: logger,
	}
}

// NewQUICDialerWithoutResolver is like NewQUICDialerWithResolver
// except that there is no configured resolver. So, if you pass in
// an address containing a domain name, the dial will fail with
// the ErrNoResolver failure.
func NewQUICDialerWithoutResolver(listener model.UDPListener, logger model.DebugLogger) model.QUICDialer {
	return NewQUICDialerWithResolver(listener, logger, &nullResolver{})
}

// quicDialerQUICGo dials using the lucas-clemente/quic-go library.
type quicDialerQUICGo struct {
	// UDPListener is the underlying UDPListener to use.
	UDPListener model.UDPListener

	// mockDialEarlyContext allows to mock quic.DialEarlyContext.
	mockDialEarlyContext func(ctx context.Context, pconn net.PacketConn,
		remoteAddr net.Addr, host string, tlsConfig *tls.Config,
		quicConfig *quic.Config) (quic.EarlySession, error)
}

var _ model.QUICDialer = &quicDialerQUICGo{}

// ErrInvalidIP indicates that a string is not a valid IP.
var ErrInvalidIP = errors.New("netxlite: invalid IP")

// ParseUDPAddr maps the string representation of an UDP endpoint to the
// corresponding *net.UDPAddr representation.
func ParseUDPAddr(address string) (*net.UDPAddr, error) {
	addr, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		return nil, ErrInvalidIP
	}
	dport, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	udpAddr := &net.UDPAddr{
		IP:   ipAddr,
		Port: dport,
		Zone: "",
	}
	return udpAddr, nil
}

// DialContext implements QUICDialer.DialContext. This function will
// apply the following TLS defaults:
//
// 1. if tlsConfig.RootCAs is nil, we use the Mozilla CA that we
// bundle with this measurement library;
//
// 2. if tlsConfig.NextProtos is empty _and_ the port is 443 or 8853,
// then we configure, respectively, "h3" and "dq".
func (d *quicDialerQUICGo) DialContext(ctx context.Context, network string,
	address string, tlsConfig *tls.Config, quicConfig *quic.Config) (
	quic.EarlySession, error) {
	pconn, err := d.UDPListener.Listen(&net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	udpAddr, err := ParseUDPAddr(address)
	if err != nil {
		return nil, err
	}
	tlsConfig = d.maybeApplyTLSDefaults(tlsConfig, udpAddr.Port)
	sess, err := d.dialEarlyContext(
		ctx, pconn, udpAddr, address, tlsConfig, quicConfig)
	if err != nil {
		pconn.Close() // we own it on failure
		return nil, err
	}
	return &quicSessionOwnsConn{EarlySession: sess, conn: pconn}, nil
}

func (d *quicDialerQUICGo) dialEarlyContext(ctx context.Context,
	pconn net.PacketConn, remoteAddr net.Addr, address string,
	tlsConfig *tls.Config, quicConfig *quic.Config) (quic.EarlySession, error) {
	if d.mockDialEarlyContext != nil {
		return d.mockDialEarlyContext(
			ctx, pconn, remoteAddr, address, tlsConfig, quicConfig)
	}
	return quic.DialEarlyContext(
		ctx, pconn, remoteAddr, address, tlsConfig, quicConfig)
}

// maybeApplyTLSDefaults ensures that we're using our certificate pool, if
// needed, and that we use a suitable ALPN, if needed, for h3 and dq.
func (d *quicDialerQUICGo) maybeApplyTLSDefaults(config *tls.Config, port int) *tls.Config {
	config = config.Clone()
	if config.RootCAs == nil {
		config.RootCAs = defaultCertPool
	}
	if len(config.NextProtos) <= 0 {
		switch port {
		case 443:
			config.NextProtos = []string{"h3"}
		case 8853:
			// See https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-10
			config.NextProtos = []string{"dq"}
		}
	}
	return config
}

// CloseIdleConnections closes idle connections.
func (d *quicDialerQUICGo) CloseIdleConnections() {
	// nothing to do
}

// quicSessionOwnsConn ensures that we close the UDPLikeConn.
type quicSessionOwnsConn struct {
	// EarlySession is the embedded early session
	quic.EarlySession

	// conn is the connection we own
	conn model.UDPLikeConn
}

// CloseWithError implements quic.EarlySession.CloseWithError.
func (sess *quicSessionOwnsConn) CloseWithError(
	code quic.ApplicationErrorCode, reason string) error {
	err := sess.EarlySession.CloseWithError(code, reason)
	sess.conn.Close()
	return err
}

// quicDialerResolver is a dialer that uses the configured Resolver
// to resolve a domain name to IP addrs.
type quicDialerResolver struct {
	// Dialer is the underlying QUICDialer.
	Dialer model.QUICDialer

	// Resolver is the underlying Resolver.
	Resolver model.Resolver
}

var _ model.QUICDialer = &quicDialerResolver{}

// DialContext implements QUICDialer.DialContext. This function
// will apply the following TLS defaults:
//
// 1. if tlsConfig.ServerName is empty, we will use the hostname
// contained inside of the `address` endpoint.
func (d *quicDialerResolver) DialContext(
	ctx context.Context, network, address string,
	tlsConfig *tls.Config, quicConfig *quic.Config) (quic.EarlySession, error) {
	onlyhost, onlyport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := d.lookupHost(ctx, onlyhost)
	if err != nil {
		return nil, err
	}
	tlsConfig = d.maybeApplyTLSDefaults(tlsConfig, onlyhost)
	// See TODO(https://github.com/ooni/probe/issues/1779) however
	// this is less of a problem for QUIC because so far we have been
	// using it to perform research only (i.e., urlgetter).
	addrs = quirkSortIPAddrs(addrs)
	var errorslist []error
	for _, addr := range addrs {
		target := net.JoinHostPort(addr, onlyport)
		sess, err := d.Dialer.DialContext(
			ctx, network, target, tlsConfig, quicConfig)
		if err == nil {
			return sess, nil
		}
		errorslist = append(errorslist, err)
	}
	return nil, quirkReduceErrors(errorslist)
}

// maybeApplyTLSDefaults sets the SNI if it's not already configured.
func (d *quicDialerResolver) maybeApplyTLSDefaults(config *tls.Config, host string) *tls.Config {
	config = config.Clone()
	if config.ServerName == "" {
		config.ServerName = host
	}
	return config
}

// lookupHost performs a domain name resolution.
func (d *quicDialerResolver) lookupHost(ctx context.Context, hostname string) ([]string, error) {
	if net.ParseIP(hostname) != nil {
		return []string{hostname}, nil
	}
	return d.Resolver.LookupHost(ctx, hostname)
}

// CloseIdleConnections implements QUICDialer.CloseIdleConnections.
func (d *quicDialerResolver) CloseIdleConnections() {
	d.Dialer.CloseIdleConnections()
	d.Resolver.CloseIdleConnections()
}

// quicDialerLogger is a dialer with logging.
type quicDialerLogger struct {
	// Dialer is the underlying QUIC dialer.
	Dialer model.QUICDialer

	// Logger is the underlying logger.
	Logger model.DebugLogger

	// operationSuffix is appended to the operation name.
	//
	// We use this suffix to distinguish the output from dialing
	// with the output from dialing an IP address when we are
	// using a dialer without resolver, where otherwise both lines
	// would read something like `dial 8.8.8.8:443...`
	operationSuffix string
}

var _ model.QUICDialer = &quicDialerLogger{}

// DialContext implements QUICContextDialer.DialContext.
func (d *quicDialerLogger) DialContext(
	ctx context.Context, network, address string,
	tlsConfig *tls.Config, quicConfig *quic.Config) (quic.EarlySession, error) {
	logcat.Tracef("quic_dial%s %s/%s...", d.operationSuffix, address, network)
	sess, err := d.Dialer.DialContext(ctx, network, address, tlsConfig, quicConfig)
	if err != nil {
		logcat.Tracef("quic_dial%s %s/%s... %s", d.operationSuffix,
			address, network, err)
		return nil, err
	}
	logcat.Tracef("quic_dial%s %s/%s... ok", d.operationSuffix, address, network)
	return sess, nil
}

// CloseIdleConnections implements QUICDialer.CloseIdleConnections.
func (d *quicDialerLogger) CloseIdleConnections() {
	d.Dialer.CloseIdleConnections()
}

// NewSingleUseQUICDialer is like NewSingleUseDialer but for QUIC.
func NewSingleUseQUICDialer(sess quic.EarlySession) model.QUICDialer {
	return &quicDialerSingleUse{sess: sess}
}

// quicDialerSingleUse is the QUICDialer returned by NewSingleQUICDialer.
type quicDialerSingleUse struct {
	mu   sync.Mutex
	sess quic.EarlySession
}

var _ model.QUICDialer = &quicDialerSingleUse{}

// DialContext implements QUICDialer.DialContext.
func (s *quicDialerSingleUse) DialContext(
	ctx context.Context, network, addr string, tlsCfg *tls.Config,
	cfg *quic.Config) (quic.EarlySession, error) {
	var sess quic.EarlySession
	defer s.mu.Unlock()
	s.mu.Lock()
	if s.sess == nil {
		return nil, ErrNoConnReuse
	}
	sess, s.sess = s.sess, nil
	return sess, nil
}

// CloseIdleConnections closes idle connections.
func (s *quicDialerSingleUse) CloseIdleConnections() {
	// nothing to do
}

// quicListenerErrWrapper is a UDPListener that wraps errors.
type quicListenerErrWrapper struct {
	// UDPListener is the underlying listener.
	model.UDPListener
}

var _ model.UDPListener = &quicListenerErrWrapper{}

// Listen implements UDPListener.Listen.
func (qls *quicListenerErrWrapper) Listen(addr *net.UDPAddr) (model.UDPLikeConn, error) {
	pconn, err := qls.UDPListener.Listen(addr)
	if err != nil {
		return nil, NewErrWrapper(classifyGenericError, QUICListenOperation, err)
	}
	return &quicErrWrapperUDPLikeConn{pconn}, nil
}

// quicErrWrapperUDPLikeConn is a UDPLikeConn that wraps errors.
type quicErrWrapperUDPLikeConn struct {
	// UDPLikeConn is the underlying conn.
	model.UDPLikeConn
}

var _ model.UDPLikeConn = &quicErrWrapperUDPLikeConn{}

// WriteTo implements UDPLikeConn.WriteTo.
func (c *quicErrWrapperUDPLikeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	count, err := c.UDPLikeConn.WriteTo(p, addr)
	if err != nil {
		return 0, NewErrWrapper(classifyGenericError, WriteToOperation, err)
	}
	return count, nil
}

// ReadFrom implements UDPLikeConn.ReadFrom.
func (c *quicErrWrapperUDPLikeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPLikeConn.ReadFrom(b)
	if err != nil {
		return 0, nil, NewErrWrapper(classifyGenericError, ReadFromOperation, err)
	}
	return n, addr, nil
}

// Close implements UDPLikeConn.Close.
func (c *quicErrWrapperUDPLikeConn) Close() error {
	err := c.UDPLikeConn.Close()
	if err != nil {
		return NewErrWrapper(classifyGenericError, ReadFromOperation, err)
	}
	return nil
}

// quicDialerErrWrapper is a dialer that performs quic err wrapping
type quicDialerErrWrapper struct {
	model.QUICDialer
}

// DialContext implements ContextDialer.DialContext
func (d *quicDialerErrWrapper) DialContext(
	ctx context.Context, network string, host string,
	tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
	sess, err := d.QUICDialer.DialContext(ctx, network, host, tlsCfg, cfg)
	if err != nil {
		return nil, NewErrWrapper(
			classifyQUICHandshakeError, QUICHandshakeOperation, err)
	}
	return sess, nil
}
