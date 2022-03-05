package archival

//
// Saver implementation
//

import (
	"sync"
	"time"
)

// Saver allows to save network, DNS, QUIC, TLS, HTTP events.
//
// You MUST use NewSaver to create a new instance.
type Saver struct {
	// aggregate aggregates network events.
	aggregate bool

	// mu provides mutual exclusion.
	mu sync.Mutex

	// nlast is the last time we emitted I/O metrics.
	nlast time.Time

	// nrecv is the number of bytes received.
	nrecv int64

	// nsent is the number of bytes sent.
	nsent int64

	// trace is the current trace.
	trace *Trace
}

// NewSaver creates a new Saver instance.
//
// You MUST use this function to create a Saver.
func NewSaver() *Saver {
	return &Saver{
		aggregate: false,
		mu:        sync.Mutex{},
		nlast:     time.Now(),
		nrecv:     0,
		nsent:     0,
		trace:     &Trace{},
	}
}

// MoveOutTrace moves the current trace out of the saver and
// creates a new empty trace inside it.
func (s *Saver) MoveOutTrace() *Trace {
	s.mu.Lock()
	if s.aggregate {
		s.emitIOMetricsLocked(time.Now())
	}
	t := s.trace
	s.trace = &Trace{}
	s.mu.Unlock()
	return t
}

func (s *Saver) maybeEmitIOMetricsLocked() {
	const interval = 250 * time.Millisecond
	if now := time.Now(); now.Sub(s.nlast) > interval {
		s.emitIOMetricsLocked(now)
	}
}

func (s *Saver) emitIOMetricsLocked(now time.Time) {
	s.trace.Network = append(s.trace.Network, &FlatNetworkEvent{
		Count:      s.nrecv,
		Failure:    "",
		Finished:   now,
		Network:    "",
		Operation:  "bytes_read",
		RemoteAddr: "",
		Started:    now,
	})
	s.trace.Network = append(s.trace.Network, &FlatNetworkEvent{
		Count:      s.nsent,
		Failure:    "",
		Finished:   now,
		Network:    "",
		Operation:  "bytes_written",
		RemoteAddr: "",
		Started:    now,
	})
	s.nlast = now
	s.nrecv, s.nsent = 0, 0
}

func (s *Saver) startAggregatingNetworkEvents() {
	s.mu.Lock()
	s.aggregate = true
	s.mu.Unlock()
}
