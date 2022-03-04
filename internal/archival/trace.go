package archival

//
// Trace implementation
//

// Trace contains the events.
type Trace struct {
	// DNSLookup contains DNSLookup events.
	DNSLookup []*FlatDNSLookupEvent

	// DNSRoundTrip contains DNSRoundTrip events.
	DNSRoundTrip []*FlatDNSRoundTripEvent

	// HTTPRoundTrip contains HTTPRoundTrip round trip events.
	HTTPRoundTrip []*FlatHTTPRoundTripEvent

	// Network contains network events.
	Network []*FlatNetworkEvent

	// QUICTLSHandshake contains QUICTLSHandshake handshake events.
	QUICTLSHandshake []*FlatQUICTLSHandshakeEvent

	// TCPConnect contains TCP connect events.
	TCPConnect []*FlatNetworkEvent
}
