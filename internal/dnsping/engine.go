package dnsping

//
// Engine
//
// The dnsping engine
//

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/miekg/dns"
)

// SinglePingPlan is the plan to perform a single DNS ping.
type SinglePingPlan struct {
	// ResolverAddress is the resolver's address (e.g., 8.8.8.8:53).
	ResolverAddress string

	// Delay is the delay since the beginning of the ping
	// session after which we should send this ping.
	//
	// The maximum timeout of the ping session is equal to the
	// maximum delay plus the engine's DNSTimeout.
	Delay time.Duration

	// Domain is the domain to query. If the domain is not a
	// FQDN, we'll convert it to FQDN form. For example, this
	// means that we'll convert `x.org` to `x.org.`.
	Domain string

	// QueryType is the type of query to send. We accept the
	// following query types: `dns.Type{A,AAAA,HTTPS}`.
	QueryType uint16
}

// NewDefaultPlans creates plans with the given number of repetitions.
func NewDefaultPlans(domain string, queryType uint16,
	resolver string, repetitions int) (out []*SinglePingPlan) {
	for idx := 0; idx < repetitions; idx++ {
		out = append(out, &SinglePingPlan{
			ResolverAddress: resolver,
			Delay:           time.Duration(idx) * time.Second,
			Domain:          domain,
			QueryType:       queryType,
		})
	}
	return out
}

// SinglePingReply is one of the replies to a single DNS ping. In
// principle, there should only be one, but there may be more than
// one with censorship or packet duplication.
type SinglePingReply struct {
	// ID is the unique ID of this reply.
	ID int64

	// SourceAddress is the address from which we received the reply.
	SourceAddress string

	// Reply contains the bytes of the DNS reply.
	Reply []byte

	// Error is the (netxlite-wrapped) error that occurred. We can
	// see two kinds of errors here:
	//
	// 1. errors that depend on the Rcode (e.g., dns_nxdomain_error);
	//
	// 2. errors that depend on the response not containing any
	// valid IP address (e.g., dns_no_answers).
	Error archival.FlatFailure

	// Finished is when we received this ping reply.
	Finished time.Time

	// Addresses contains the resolved addresses.
	Addresses []string

	// ALPNs contains the resolved ALPNs.
	ALPNs []string
}

// SinglePingResult is the result of a single DNS ping. In most
// cases, each query will receive a single reply, but with censorship
// and packet duplication we may receive more than one (or none).
type SinglePingResult struct {
	// ID is the unique ID of this result.
	ID int64

	// ResolverAddress is the resolver's address (e.g., 8.8.8.8:53).
	ResolverAddress string

	// Domain is the domain we queried. If the domain is not
	// a FQDN, we'll convert it to FQDN form. For example, this
	// means that we'll convert `x.org` to `x.org.`.
	Domain string

	// QueryType is the type of query we sent. We accept the
	// following query types: `dns.Type{A,AAAA,HTTPS}`.
	QueryType uint16

	// QueryID is the query ID.
	QueryID uint16

	// Query contains the bytes of the query we have sent.
	Query []byte

	// Started is when we sent the query.
	Started time.Time

	// Replies contains the replies for this query. This field will
	// be empty if we've got no replies. In the common case, it
	// will contain just one entry. It may contain more than one
	// entry in case of censorship or packet duplication.
	Replies []*SinglePingReply
}

// Result is the result of a DNS ping session.
type Result struct {
	// Pings contains a list of ping results. If this list is empty,
	// it means the input plan was empty as well.
	Pings []*SinglePingResult
}

// Engine is the engine performing a DNS ping session. To initialize, fill all
// the fields marked as MANDATORY, or just use the NewEngine constructor.
type Engine struct {
	// Decoder is the MANDATORY specific DNSDecoder to use.
	Decoder model.DNSDecoder

	// Encoder is the specific MANDATORY DNSEncoder to use.
	Encoder model.DNSEncoder

	// IDGenerator is the MANDATORY IDGenerator to use.
	IDGenerator *measurex.IDGenerator

	// Listener is the specific MANDATORY UDPListener to use.
	Listener model.UDPListener

	// Logger is the MANDATORY logger to use.
	Logger model.Logger

	// QueryTimeout is the MANDATORY query timeout to use.
	QueryTimeout time.Duration
}

// NewEngine creates a new  engine instance using the given
// logger, the given generator, and typical values for other fields.
func NewEngine(logger model.Logger, idgen *measurex.IDGenerator) *Engine {
	return &Engine{
		Decoder:      &netxlite.DNSDecoderMiekg{},
		Encoder:      &netxlite.DNSEncoderMiekg{},
		IDGenerator:  idgen,
		Listener:     netxlite.NewUDPListener(),
		Logger:       logger,
		QueryTimeout: 4 * time.Second,
	}
}

// RunAsync runs the Engine asynchronously and returns the
// channel on which we'll post the overall result when done.
func (e *Engine) RunAsync(
	ctx context.Context, plans []*SinglePingPlan) <-chan *Result {
	const buffered = 1 // so early exit allows to collect goroutine earlier
	chout := make(chan *Result, buffered)
	go e.worker(ctx, plans, chout)
	return chout
}

// worker is the Engine worker. It emits the result on c.
func (e *Engine) worker(
	ctx context.Context, plans []*SinglePingPlan, c chan<- *Result) {
	// Implementation note: createSchedule works on a copy of the plan to
	// avoid data races and produces a schedule that we can follow
	c <- e.followThePlans(ctx, e.createSchedule(plans))
}

// schedule is a scheduled list of SinglePingPlan instances
type schedule struct {
	maxDelay time.Duration
	p        []*SinglePingPlan
}

// createSchedule returns a copy of the original plans where we've sorted
// by Delay and made each delay relative to the previous one.
func (e *Engine) createSchedule(in []*SinglePingPlan) (out *schedule) {
	out = &schedule{}
	if len(in) < 1 {
		return out
	}
	// 1. we need to deep copy to avoid data races
	for _, plan := range in {
		out.p = append(out.p, &SinglePingPlan{
			ResolverAddress: plan.ResolverAddress,
			Delay:           plan.Delay,
			Domain:          plan.Domain,
			QueryType:       plan.QueryType,
		})
	}
	// 2. now we can safely mutate.
	sort.SliceStable(out.p, func(i, j int) bool {
		return out.p[i].Delay < out.p[j].Delay
	})
	// 3. compute the deadline
	out.maxDelay = out.p[len(out.p)-1].Delay + e.QueryTimeout
	// 4. finally make the delays relative to each other.
	var prevDelay time.Duration
	for _, plan := range out.p {
		delta := plan.Delay - prevDelay
		prevDelay = plan.Delay
		plan.Delay = delta
	}
	return
}

// followThePlans implements the Engine algorithm. This function
// always returns a valid non-nil Result.
func (e *Engine) followThePlans(ctx context.Context, s *schedule) (out *Result) {
	out = &Result{}
	// 1. if we don't have anything to do, shortcut the return
	if len(s.p) < 1 {
		return
	}
	// 2. create UDP socket.
	pconn, err := e.Listener.Listen(&net.UDPAddr{})
	if err != nil {
		// Because this error should not commonly happen, we don't bother
		// with recording it into the results.
		e.Logger.Warnf("cannot create UDP socket: %s", err.Error())
		return
	}
	defer pconn.Close() // we own the connection
	// 3. create board and spawn goroutines
	wg := &sync.WaitGroup{}
	wg.Add(2)
	board := &dnsPingBoard{
		decoder:     e.Decoder,
		idGenerator: e.IDGenerator,
		logger:      e.Logger,
		mu:          sync.Mutex{},
		replies:     []*SinglePingResult{},
	}
	go e.sender(wg, board, pconn, s.p)
	go e.receiver(wg, board, pconn)
	// 4. wait for completion
	select {
	case <-time.After(s.maxDelay):
	case <-ctx.Done():
	}
	pconn.Close() // explicitly interrupt the goroutines
	wg.Wait()     // wait for goroutines to join
	out = board.toResult()
	return
}

// sender is the sender goroutine.
func (e *Engine) sender(wg *sync.WaitGroup, board *dnsPingBoard,
	pconn net.PacketConn, plans []*SinglePingPlan) {
	defer wg.Done() // synchronize with the parent
	for _, plan := range plans {
		time.Sleep(plan.Delay)
		data, qid, err := e.Encoder.Encode(plan.Domain, plan.QueryType, false)
		if err != nil {
			// This error should not happen unless the caller really screws
			// up when creating the plan. So, it is a programmer error and it
			// makes sense to just emit a warning on the console.
			e.Logger.Warnf("dnsping: cannot encode: %s", err.Error())
			continue
		}
		result := &SinglePingResult{
			ID:              e.IDGenerator.Next(),
			ResolverAddress: plan.ResolverAddress,
			Domain:          plan.Domain,
			QueryType:       plan.QueryType,
			QueryID:         qid,
			Query:           data,
			Started:         time.Now(),
			Replies:         []*SinglePingReply{},
		}
		destAddr, err := e.resolveAddr(plan.ResolverAddress)
		if err != nil {
			// Likewise also this error seems very unlikely.
			e.Logger.Warnf("dnsping: cannot resolve addr: %s", err.Error())
			continue
		}
		if _, err := pconn.WriteTo(data, destAddr); err != nil {
			if errors.Is(err, net.ErrClosed) {
				// This is when the parent has close the connection to
				// inform us we should be terminating.
				break
			}
			// Likewise also this error seems quite unlikely.
			e.Logger.Warnf("dnsping: cannot send: %s", err.Error())
			continue
		}
		board.sent(result)
	}
}

// ErrNotIPAddr indicates that you passed DNS ping an endpoint
// address containing a domain name instead of an IP addr.
var ErrNotIPAddr = errors.New("dnsping: passed an address containing a domain name")

// resolveAddr maps address to an UDPAddr.
func (e *Engine) resolveAddr(address string) (*net.UDPAddr, error) {
	addr, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		return nil, ErrNotIPAddr
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

// receiver is the receiver goroutine.
func (e *Engine) receiver(wg *sync.WaitGroup, board *dnsPingBoard, pconn net.PacketConn) {
	defer wg.Done() // synchronize with the parent
	for {
		buffer := make([]byte, 1<<13) // definitely enough room
		count, srcAddr, err := pconn.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// This is when the parent has close the connection to
				// inform us we should be terminating.
				break
			}
			// Likewise also this error seems quite unlikely.
			e.Logger.Warnf("dnsping: cannot recv: %s", err.Error())
			continue
		}
		board.received(time.Now(), buffer[:count], srcAddr)
	}
}

// dnsPingBoard keeps track of what we've sent and received so far.
type dnsPingBoard struct {
	// decoder contains the DNSDecoder to use.
	decoder model.DNSDecoder

	// idGenerator points to the IDGenerator to use.
	idGenerator *measurex.IDGenerator

	// logger contains the logger to use.
	logger model.Logger

	// mu provides mutual exclusion.
	mu sync.Mutex

	// replies contains the pending replies.
	replies []*SinglePingResult
}

// toResult converts the internal content to a Result.
func (b *dnsPingBoard) toResult() *Result {
	b.mu.Lock()
	r := b.replies
	b.replies = []*SinglePingResult{}
	b.mu.Unlock()
	return &Result{
		Pings: r,
	}
}

// sent is called after we've sent a query.
func (b *dnsPingBoard) sent(r *SinglePingResult) {
	b.mu.Lock()
	b.replies = append(b.replies, r)
	b.mu.Unlock()
}

// received is called when recvfrom returns successfully.
func (b *dnsPingBoard) received(now time.Time, data []byte, srcAddr net.Addr) {
	defer b.mu.Unlock()
	b.mu.Lock()
	reply, err := b.decoder.ParseReply(data)
	if err != nil {
		// TODO(bassosimone): should we store this message?
		b.logger.Warnf("dnsping: cannot parse reply: %s", err.Error())
		return
	}
	result, found := b.findResultLocked(reply)
	if !found {
		// TODO(bassosimone): should we store this message?
		b.logger.Warnf("dnsping: reply with unknown ID: %s", err.Error())
		return
	}
	b.logger.Infof("🔔 [dnsping] %s for %s/%s from %s in %s",
		dns.RcodeToString[reply.Rcode], result.Domain,
		dns.TypeToString[result.QueryType], srcAddr.String(),
		now.Sub(result.Started))
	addrs, alpns, err := b.finishParsingLocked(result.QueryType, reply)
	result.Replies = append(result.Replies, &SinglePingReply{
		ID:            b.idGenerator.Next(),
		SourceAddress: srcAddr.String(),
		Reply:         data,
		Error:         b.errorToWrappedFlatFailure(err),
		Finished:      now,
		Addresses:     addrs,
		ALPNs:         alpns,
	})
}

// findResultLocked returns the matching result. This function
// assumes to be invoked after the mutex has been locked.
func (b *dnsPingBoard) findResultLocked(reply *dns.Msg) (*SinglePingResult, bool) {
	// Implementation note: linear search faster for small N
	for _, entry := range b.replies {
		if reply.Id == entry.QueryID {
			return entry, true
		}
	}
	return nil, false
}

// finishParsingLocked finishes parsing the reply. This function
// assumes to be invoked after the mutex has been locked.
func (b *dnsPingBoard) finishParsingLocked(
	qtype uint16, reply *dns.Msg) (addrs []string, alpns []string, err error) {
	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		addrs, err := b.decoder.DecodeReplyLookupHost(qtype, reply)
		if err != nil {
			return nil, nil, err
		}
		return addrs, []string{}, nil
	case dns.TypeHTTPS:
		https, err := b.decoder.DecodeReplyLookupHTTPS(reply)
		if err != nil {
			return nil, nil, err
		}
		var addrs []string
		addrs = append(addrs, https.IPv4...)
		addrs = append(addrs, https.IPv6...)
		return addrs, https.ALPN, nil
	default:
		return []string{}, []string{}, nil
	}
}

// errorToWrappedFlatFailure wraps the error and converts it to a flat failure.
func (b *dnsPingBoard) errorToWrappedFlatFailure(err error) (out archival.FlatFailure) {
	if err != nil {
		out = archival.NewFlatFailure(netxlite.NewErrWrapper(
			netxlite.ClassifyResolverError,
			netxlite.ResolveOperation, err))
	}
	return
}
