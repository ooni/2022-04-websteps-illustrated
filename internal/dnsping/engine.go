package dnsping

//
// Engine
//
// The dnsping engine
//

import (
	"sort"
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

	// Rcode contains the response rcode.
	Rcode string

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

// QueryTypeAsString returns the QueryType as string.
func (spr *SinglePingResult) QueryTypeAsString() string {
	return dns.TypeToString[spr.QueryType]
}

// Result is the result of a DNS ping session.
type Result struct {
	// Pings contains a list of ping results. If this list is empty,
	// it means the input plan was empty or wrong.
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

// RunAsync runs the Engine asynchronously and returns the channel
// on which we'll post the overall result when done. The channel we
// return is buffered, so you're not going to leak goroutines if
// you just decide to stop waiting on the channel earlier.
func (e *Engine) RunAsync(plans []*SinglePingPlan) <-chan *Result {
	const buffered = 1
	c := make(chan *Result, buffered)
	go e.worker(plans, c)
	return c
}

// worker is the Engine worker. It emits the result on c.
func (e *Engine) worker(plans []*SinglePingPlan, c chan<- *Result) {
	if len(plans) < 1 {
		c <- &Result{} // shortcut
		return
	}
	e.stickToTheSchedule(e.createSchedule(plans), c)
}

// schedule is a scheduled list of SinglePingPlan instances
type schedule struct {
	p []*SinglePingPlan
}

// createSchedule returns a copy of the original plans where we've sorted
// by Delay and made each delay relative to the previous one.
func (e *Engine) createSchedule(in []*SinglePingPlan) (out *schedule) {
	out = &schedule{}
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
	// 3. finally make the delays relative to each other.
	var prevDelay time.Duration
	for _, plan := range out.p {
		delta := plan.Delay - prevDelay
		prevDelay = plan.Delay
		plan.Delay = delta
	}
	return
}

// stickToTheSchedule implements the Engine algorithm. This function
// always returns a valid non-nil Result.
func (e *Engine) stickToTheSchedule(s *schedule, c chan<- *Result) {
	out := &Result{}
	wg := &sync.WaitGroup{}
	pings := make(chan *resultWrapper, len(s.p)) // all writes nonblocking
	for _, plan := range s.p {
		time.Sleep(plan.Delay) // wait for our turn to run
		wg.Add(1)
		deadline := time.Now().Add(e.QueryTimeout)
		go e.singlePinger(wg, plan, deadline, pings)
	}
	for len(out.Pings) < len(s.p) {
		rw := <-pings
		if rw.Err != nil {
			continue // something was fundamentally wrong here
		}
		out.Pings = append(out.Pings, rw.Result)
	}
	wg.Wait() // synchronize with pingers
	c <- out
}

type resultWrapper struct {
	// Err indicates a fundamental error inside singlePinger.
	Err error

	// Result is the SinglePingResult.
	Result *SinglePingResult
}

// singlePinger sends a ping and then waits for one or multiple replies
// for the original query being sent. The reason why each ping uses a
// different UDP socket is the following. We have experimentally observed
// that an endpoint that has emitted a censored query may be completely
// blocked for quite some time. Therefore, an observer may only see
// one or just a few replies using the same UDP socket. Conversely, we
// avoid this issue by using a new UDP socket for each ping.
func (e *Engine) singlePinger(wg *sync.WaitGroup, plan *SinglePingPlan,
	deadline time.Time, out chan<- *resultWrapper) {

	// synchronize with the parent
	defer wg.Done()

	// encode the query
	rawQuery, qid, err := e.Encoder.Encode(plan.Domain, plan.QueryType, false)
	if err != nil {
		e.Logger.Warnf("dnsping: cannot encode query: %s", err.Error())
		out <- &resultWrapper{Err: err}
		return
	}

	// send the query
	pconn, expectedAddr, err := netxlite.DNSOverUDPWriteRawQueryTo(
		e.Listener, plan.ResolverAddress, rawQuery)
	if err != nil {
		e.Logger.Warnf("dnsping: cannot send query: %s", err.Error())
		out <- &resultWrapper{Err: err}
		return
	}
	defer pconn.Close() // we own the connection

	// start collecting replies
	var flags int64
	flags |= netxlite.DNSOverUDPIncludeRepliesFromUnexpectedServers
	flags |= netxlite.DNSOverUDPCollectMultipleReplies
	flags |= netxlite.DNSOverUDPOmitTimeoutIfSomeRepliesReturned
	rrch := netxlite.DNSOverUDPReadRawRepliesFrom(pconn, expectedAddr, deadline, flags)

	// start filling in the result struct
	result := &SinglePingResult{
		ID:              e.IDGenerator.Next(),
		ResolverAddress: plan.ResolverAddress,
		Domain:          plan.Domain,
		QueryType:       plan.QueryType,
		QueryID:         qid,
		Query:           rawQuery,
		Started:         time.Now(),
		Replies:         []*SinglePingReply{},
	}

	// process raw round trip results
	for rr := range rrch {
		e.received(plan.ResolverAddress, result, rr)
	}

	// send result to parent.
	out <- &resultWrapper{Result: result}
}

// received is called when recvfrom returns successfully.
func (e *Engine) received(sourceAddress string,
	result *SinglePingResult, rr *netxlite.DNSOverUDPRawReply) {
	if rr.Error != nil {
		result.Replies = append(result.Replies, &SinglePingReply{
			ID:            e.IDGenerator.Next(),
			SourceAddress: sourceAddress,
			Reply:         []byte{},
			Error:         archival.NewFlatFailure(rr.Error),
			Finished:      rr.Received,
			Rcode:         "",
			Addresses:     []string{},
			ALPNs:         []string{},
		})
		return
	}
	reply, err := e.Decoder.ParseReply(rr.RawReply, result.QueryID)
	if err != nil {
		result.Replies = append(result.Replies, &SinglePingReply{
			ID:            e.IDGenerator.Next(),
			SourceAddress: sourceAddress,
			Reply:         rr.RawReply,
			Error:         archival.NewFlatFailure(err),
			Finished:      rr.Received,
			Rcode:         "",
			Addresses:     []string{},
			ALPNs:         []string{},
		})
		return
	}
	if !rr.ValidSourceAddr {
		result.Replies = append(result.Replies, &SinglePingReply{
			ID:            e.IDGenerator.Next(),
			SourceAddress: sourceAddress,
			Reply:         rr.RawReply,
			Error:         archival.FlatFailure(netxlite.FailureDNSReplyFromUnexpectedServer),
			Finished:      rr.Received,
			Rcode:         dns.RcodeToString[reply.Rcode],
			Addresses:     []string{},
			ALPNs:         []string{},
		})
		return
	}
	emojis := map[bool]string{
		false: "🔔",
		true:  "❓",
	}
	emoji := emojis[len(result.Replies) > 0]
	e.Logger.Infof("%s [dnsping] %s for %s/%s from %s in %s with dns.id %d",
		emoji, dns.RcodeToString[reply.Rcode], result.Domain,
		result.QueryTypeAsString(), sourceAddress,
		rr.Received.Sub(result.Started), reply.Id)
	addrs, alpns, err := e.finishParsing(result.QueryType, reply)
	result.Replies = append(result.Replies, &SinglePingReply{
		ID:            e.IDGenerator.Next(),
		SourceAddress: sourceAddress,
		Reply:         rr.RawReply,
		Error:         e.errorToWrappedFlatFailure(err),
		Finished:      rr.Received,
		Rcode:         dns.RcodeToString[reply.Rcode],
		Addresses:     addrs,
		ALPNs:         alpns,
	})
}

// finishParsing finishes parsing the reply.
func (e *Engine) finishParsing(
	qtype uint16, reply *dns.Msg) (addrs []string, alpns []string, err error) {
	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		addrs, err := e.Decoder.DecodeReplyLookupHost(qtype, reply)
		if err != nil {
			return nil, nil, err
		}
		return addrs, []string{}, nil
	case dns.TypeHTTPS:
		https, err := e.Decoder.DecodeReplyLookupHTTPS(reply)
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
func (e *Engine) errorToWrappedFlatFailure(err error) (out archival.FlatFailure) {
	if err != nil {
		out = archival.NewFlatFailure(netxlite.NewErrWrapper(
			netxlite.ClassifyResolverError,
			netxlite.ResolveOperation, err))
	}
	return
}
