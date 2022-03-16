package netxlite

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// DNSOverUDPTransport is a DNS-over-UDP DNSTransport.
type DNSOverUDPTransport struct {
	dialer  model.Dialer
	address string
}

// NewDNSOverUDPTransport creates a DNSOverUDP instance.
//
// Arguments:
//
// - dialer is any type that implements the Dialer interface;
//
// - address is the endpoint address (e.g., 8.8.8.8:53).
func NewDNSOverUDPTransport(dialer model.Dialer, address string) *DNSOverUDPTransport {
	return &DNSOverUDPTransport{dialer: dialer, address: address}
}

// RoundTrip sends a query and receives a reply.
func (t *DNSOverUDPTransport) RoundTrip(ctx context.Context, rawQuery []byte) ([]byte, error) {
	listener := NewUDPListener()
	pconn, expectedAddr, err := DNSOverUDPWriteRawQueryTo(listener, t.address, rawQuery)
	if err != nil {
		return nil, err
	}
	defer pconn.Close() // we own it
	// Use five seconds timeout like Bionic does. See
	// https://labs.ripe.net/Members/baptiste_jonglez_1/persistent-dns-connections-for-reliability-and-performance
	deadline := time.Now().Add(5 * time.Second)
	const flags = 0 // default behavior for a DNS resolver
	ch := DNSOverUDPReadRawRepliesFrom(pconn, expectedAddr, deadline, flags)
	defer func() {
		// ensure we drain the channel and mention there is a bug if we see more events
		for ev := range ch {
			log.Printf("BUG: unexpected message on channel: %+v", ev)
		}
	}()
	rr := <-ch
	if rr.Error != nil {
		return nil, rr.Error
	}
	return rr.RawReply, nil
}

// DNSOverUDPwriteRawQueryTo sends a raw query to the given remote server.
// and returns the connection from which we'll receive replies.
func DNSOverUDPWriteRawQueryTo(listener model.UDPListener,
	serverEndpoint string, rawQuery []byte) (model.UDPLikeConn, net.Addr, error) {
	expectedAddr, err := ParseUDPAddr(serverEndpoint)
	if err != nil {
		return nil, nil, err
	}
	pconn, err := listener.Listen(&net.UDPAddr{})
	if err != nil {
		return nil, nil, err
	}
	if _, err := pconn.WriteTo(rawQuery, expectedAddr); err != nil {
		pconn.Close()
		return nil, nil, err
	}
	return pconn, expectedAddr, nil
}

// DNSOverUDPRawReply is the a raw reply returned by DNSOverUDPReadRawRepliesFrom.
type DNSOverUDPRawReply struct {
	// Error indicates that an error occurred.
	Error error

	// RawReply contains the raw reply.
	RawReply []byte

	// Received is the time when we received the reply.
	Received time.Time

	// SourceAddr is address that sent the reply.
	SourceAddr net.Addr

	// ValidSourceAddr is true if SourceAddr is equal to ExpectedAddr.
	ValidSourceAddr bool
}

const (
	// DNSOverUDPCollectMultipleReplies tells DNSOverUDPReadRawRepliesFrom to collect
	// all the replies rather than stopping after the first good one.
	DNSOverUDPCollectMultipleReplies = 1 << iota

	// DNSOverUDPIncludeRepliesFromUnexpectedServers causes DNSOverUDPReadRawRepliesFrom
	// to also include in the returned replies the ones coming from unexpected addrs.
	DNSOverUDPIncludeRepliesFromUnexpectedServers

	// DNSOverUDPOmitTimeoutIfSomeRepliesReturned causes DNSOverUDPReadRawRepliesFrom
	// to omit the final timeout error in case at least one reply was returned.
	DNSOverUDPOmitTimeoutIfSomeRepliesReturned
)

// DNSOverUDPReadRawRepliesFrom receives raw DNS replies form the given UDP conn.
//
// Arguments:
//
// - pconn is the UDP conn to use;
//
// - expectedAddr is the address from which we expect replies;
//
// - deadline is the i/o timeout deadline;
//
// - flags contains flags modifying the behavior.
//
// The return value is the channel when we emit events occurring while attempting
// to receive raw replies from the given UDP socket. The channel is closed when
// the background goroutine that attempts receiving returns.
//
// If you do not specify any flag, this function will always post a single
// DNSOverUDPRawReply entry to the returned channel. To determine whether this
// reply is successful or an error, check the .Error field.
//
// We support the following flags:
//
// 1. DNSOverUDPCollectMultipleReplies prevents this function from stopping
// receiving once it has received the first raw reply from the socket. The
// function will continue running until an error occurs. Among the errors that
// may occur, there is notably the timeout caused by the deadline.
//
// 2. DNSOverUDPIncludeRepliesFromUnexpectedServers makes this function more
// lax so that also replies coming from unexpected servers are returned. If you
// specify this flag, check the .ValidSourceAddr field to determine whether a
// returned raw reply came from the expected DNS server.
//
// 3. DNSOverUDPOmitTimeoutIfSomeRepliesReturned is such that, when we hit
// the final deadline timeout, we will not post it as an error iff we've already
// posted to the channel _at least_ one raw reply.
func DNSOverUDPReadRawRepliesFrom(pconn model.UDPLikeConn, expectedAddr net.Addr,
	deadline time.Time, flags int64) <-chan *DNSOverUDPRawReply {
	out := make(chan *DNSOverUDPRawReply)
	go dnsOverUDPReadRawRepliesFromWorker(pconn, expectedAddr, deadline, flags, out)
	return out
}

func dnsOverUDPReadRawRepliesFromWorker(pconn model.UDPLikeConn, expectedAddr net.Addr,
	deadline time.Time, flags int64, out chan<- *DNSOverUDPRawReply) {
	defer close(out)
	pconn.SetDeadline(deadline)
	var numReplies int
	for {
		buffer := make([]byte, 1<<17) // definitely enough room
		numBytes, srcAddr, err := pconn.ReadFrom(buffer)
		received := time.Now()
		if err != nil {
			if err.Error() == FailureGenericTimeoutError && numReplies > 0 &&
				(flags&DNSOverUDPOmitTimeoutIfSomeRepliesReturned) != 0 {
				return
			}
			out <- &DNSOverUDPRawReply{
				Error:           err,
				RawReply:        nil,
				Received:        received,
				SourceAddr:      nil,
				ValidSourceAddr: false,
			}
			return
		}
		isValid := expectedAddr.String() == srcAddr.String()
		if !isValid && (flags&DNSOverUDPIncludeRepliesFromUnexpectedServers) == 0 {
			log.Printf("netxlite: DNS reply from unexpected UDP server: %s", srcAddr.String())
			continue
		}
		numReplies++ // count the number of emitted replies
		out <- &DNSOverUDPRawReply{
			Error:           nil,
			RawReply:        buffer[:numBytes],
			Received:        received,
			SourceAddr:      srcAddr,
			ValidSourceAddr: isValid,
		}
		if (flags & DNSOverUDPCollectMultipleReplies) == 0 {
			return
		}
	}
}

// RequiresPadding returns false for UDP according to RFC8467.
func (t *DNSOverUDPTransport) RequiresPadding() bool {
	return false
}

// Network returns the transport network, i.e., "udp".
func (t *DNSOverUDPTransport) Network() string {
	return "udp"
}

// Address returns the upstream server address.
func (t *DNSOverUDPTransport) Address() string {
	return t.address
}

// CloseIdleConnections closes idle connections, if any.
func (t *DNSOverUDPTransport) CloseIdleConnections() {
	// nothing to do
}

var _ model.DNSTransport = &DNSOverUDPTransport{}
