package archival

//
// Saver implementation
//

import "sync"

// Saver allows to save network, DNS, QUIC, TLS, HTTP events.
//
// You MUST use NewSaver to create a new instance.
type Saver struct {
	// dcne disables collecting network events.
	dcne bool

	// mu provides mutual exclusion.
	mu sync.Mutex

	// trace is the current trace.
	trace *Trace
}

// NewSaver creates a new Saver instance.
//
// You MUST use this function to create a Saver.
func NewSaver() *Saver {
	return &Saver{
		dcne:  false,
		mu:    sync.Mutex{},
		trace: &Trace{},
	}
}

// StopCollectingNetworkEvents tells the saver that now we
// should stop collecting network events. You typically call
// this method once the QUIC/TLS handshake is finished.
func (as *Saver) StopCollectingNetworkEvents() {
	as.mu.Lock()
	as.dcne = true
	as.mu.Unlock()
}

// ResumeCollectingNetworkEvents resumes collecting network
// events after a StopCollectingNetworkEvents call.
func (as *Saver) ResumeCollectingNetworkEvents() {
	as.mu.Lock()
	as.dcne = false
	as.mu.Unlock()
}

// MoveOutTrace moves the current trace out of the saver and
// creates a new empty trace inside it.
func (as *Saver) MoveOutTrace() *Trace {
	as.mu.Lock()
	t := as.trace
	as.trace = &Trace{}
	as.mu.Unlock()
	return t
}
