package archival

//
// Code to convert to the archival JSON format.
//

import (
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/engine/geolocate"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

//
// TCP connect
//

// NewArchivalTCPConnectResultList builds a TCP connect list in the OONI archival
// data format out of the results saved inside the trace.
func (t *Trace) NewArchivalTCPConnectResultList(begin time.Time) []model.ArchivalTCPConnectResult {
	return NewArchivalTCPConnectResultList(begin, t.TCPConnect)
}

// NewArchivalTCPConnectResultList builds a TCP connect list in the OONI archival
// data format out of the results saved inside the trace.
func NewArchivalTCPConnectResultList(begin time.Time, in []*FlatNetworkEvent) (out []model.ArchivalTCPConnectResult) {
	for _, ev := range in {
		out = append(out, ev.ToArchivalTCPConnectResult(begin))
	}
	return
}

// ToArchivalTCPConnectResult converts a FlatNetworkEvent to ArchivalTCPConnectResult.
func (ev *FlatNetworkEvent) ToArchivalTCPConnectResult(begin time.Time) model.ArchivalTCPConnectResult {
	// We assume Go is passing us legit data structures
	ip, sport, _ := net.SplitHostPort(ev.RemoteAddr)
	iport, _ := strconv.Atoi(sport)
	return model.ArchivalTCPConnectResult{
		IP:   ip,
		Port: iport,
		Status: model.ArchivalTCPConnectStatus{
			Blocked: nil, // Web Connectivity only, depends on the control
			Failure: ev.Failure.ToArchivalFailure(),
			Success: ev.Failure.IsSuccess(),
		},
		T: ev.Finished.Sub(begin).Seconds(),
	}
}

//
// HTTP
//

// NewArchivalHTTPRequestResultList builds an HTTP requests list in the OONI
// archival data format out of the results saved inside the trace.
//
// This function will sort the emitted list of requests such that the last
// request that happened in time is the first one to be emitted. If the
// measurement code performs related requests sequentially (which is a kinda a
// given because you cannot follow a redirect before reading the previous request),
// then the result is sorted how the OONI pipeline expects it to be.
func (t *Trace) NewArchivalHTTPRequestResultList(begin time.Time) []model.ArchivalHTTPRequestResult {
	return NewArchivalHTTPRequestResultList(begin, t.HTTPRoundTrip)
}

// NewArchivalHTTPRequestResultList builds an HTTP requests list in the OONI
// archival data format out of the results saved inside the trace.
//
// This function will sort the emitted list of requests such that the last
// request that happened in time is the first one to be emitted. If the
// measurement code performs related requests sequentially (which is a kinda a
// given because you cannot follow a redirect before reading the previous request),
// then the result is sorted how the OONI pipeline expects it to be.
func NewArchivalHTTPRequestResultList(begin time.Time, in []*FlatHTTPRoundTripEvent) (out []model.ArchivalHTTPRequestResult) {
	for _, ev := range in {
		out = append(out, ev.ToArchival(begin))
	}
	// Implementation note: historically OONI has always added
	// the _last_ measurement in _first_ position. This has only
	// been relevant for sequentially performed requests. For
	// this purpose it feels okay to use T as the sorting key,
	// since it's the time when we exited RoundTrip().
	sort.Slice(out, func(i, j int) bool {
		return out[i].T > out[j].T
	})
	return
}

// ToArchival converts a FlatHTTPRoundTripEvent to ArchivalHTTPRequestResult.
func (ev *FlatHTTPRoundTripEvent) ToArchival(begin time.Time) model.ArchivalHTTPRequestResult {
	return model.ArchivalHTTPRequestResult{
		Failure: ev.Failure.ToArchivalFailure(),
		Request: model.ArchivalHTTPRequest{
			Body:            model.ArchivalMaybeBinaryData{},
			BodyIsTruncated: false,
			HeadersList:     ev.newHTTPHeadersList(ev.RequestHeaders),
			Headers:         ev.newHTTPHeadersMap(ev.RequestHeaders),
			Method:          ev.Method,
			Tor:             model.ArchivalHTTPTor{},
			Transport:       ev.Transport,
			URL:             ev.URL,
		},
		Response: model.ArchivalHTTPResponse{
			Body: model.ArchivalMaybeBinaryData{
				Value: string(ev.ResponseBody),
			},
			BodyIsTruncated: ev.ResponseBodyIsTruncated,
			Code:            ev.StatusCode,
			HeadersList:     ev.newHTTPHeadersList(ev.ResponseHeaders),
			Headers:         ev.newHTTPHeadersMap(ev.ResponseHeaders),
			Locations:       ev.ResponseHeaders.Values("Location"), // safe with nil headers
		},
		T: ev.Finished.Sub(begin).Seconds(),
	}
}

func (ev *FlatHTTPRoundTripEvent) newHTTPHeadersList(source http.Header) (out []model.ArchivalHTTPHeader) {
	for key, values := range source {
		for _, value := range values {
			out = append(out, model.ArchivalHTTPHeader{
				Key: key,
				Value: model.ArchivalMaybeBinaryData{
					Value: value,
				},
			})
		}
	}
	// Implementation note: we need to sort the keys to have
	// stable testing since map iteration is random.
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key < out[j].Key
	})
	return
}

func (ev *FlatHTTPRoundTripEvent) newHTTPHeadersMap(source http.Header) (out map[string]model.ArchivalMaybeBinaryData) {
	for key, values := range source {
		for index, value := range values {
			if index > 0 {
				break // only the first entry
			}
			if out == nil {
				out = make(map[string]model.ArchivalMaybeBinaryData)
			}
			out[key] = model.ArchivalMaybeBinaryData{Value: value}
		}
	}
	return
}

//
// DNS
//

// NewArchivalDNSLookupResultList builds a DNS lookups list in the OONI
// archival data format out of the results saved inside the trace.
func (t *Trace) NewArchivalDNSLookupResultList(begin time.Time) []model.ArchivalDNSLookupResult {
	return NewArchivalDNSLookupResultList(begin, t.DNSLookup)
}

// NewArchivalDNSLookupResultList builds a DNS lookups list in the OONI
// archival data format out of the results saved inside the trace.
func NewArchivalDNSLookupResultList(begin time.Time, in []*FlatDNSLookupEvent) (out []model.ArchivalDNSLookupResult) {
	for _, ev := range in {
		out = append(out, ev.ToArchival(begin)...)
	}
	return
}

// ToArchival converts a FlatDNSLookupEvent to []ArchivalDNSLookupResult.
func (ev *FlatDNSLookupEvent) ToArchival(begin time.Time) []model.ArchivalDNSLookupResult {
	switch ev.LookupType {
	case DNSLookupTypeHTTPS:
		return ev.toArchivalHTTPS(begin)
	case DNSLookupTypeGetaddrinfo:
		return ev.toArchivalGetaddrinfo(begin)
	default:
		log.Printf("ToArchivalDNSLookupResultList: unhandled record: %+v", ev)
		return []model.ArchivalDNSLookupResult{}
	}
}

func (ev *FlatDNSLookupEvent) toArchivalHTTPS(begin time.Time) (out []model.ArchivalDNSLookupResult) {
	out = append(out, model.ArchivalDNSLookupResult{
		Answers:          ev.gatherHTTPS(),
		Engine:           ev.ResolverNetwork,
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "HTTPS",
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		T:                ev.Finished.Sub(begin).Seconds(),
	})
	return
}

func (ev *FlatDNSLookupEvent) gatherHTTPS() (out []model.ArchivalDNSAnswer) {
	for _, addr := range ev.Addresses {
		answer := model.ArchivalDNSAnswer{}
		asn, org, _ := geolocate.LookupASN(addr)
		answer.ASN = int64(asn)
		answer.ASOrgName = org
		if strings.Contains(addr, ":") {
			answer.AnswerType = "AAAA"
			answer.IPv6 = addr
		} else {
			answer.AnswerType = "A"
			answer.IPv4 = addr
		}
		out = append(out, answer)
	}
	for _, alpn := range ev.ALPNs {
		answer := model.ArchivalDNSAnswer{AnswerType: "ALPN"}
		answer.ALPN = alpn
		out = append(out, answer)
	}
	return
}

func (ev *FlatDNSLookupEvent) toArchivalGetaddrinfo(begin time.Time) (out []model.ArchivalDNSLookupResult) {
	out = append(out, model.ArchivalDNSLookupResult{
		Answers:          ev.gatherA(),
		Engine:           ev.ResolverNetwork,
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "A",
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		T:                ev.Finished.Sub(begin).Seconds(),
	})
	aaaa := ev.gatherAAAA()
	if len(aaaa) <= 0 && ev.Failure.IsSuccess() {
		// We don't have any AAAA results. Historically we do not
		// create a record for AAAA with no results when A succeeds
		return
	}
	out = append(out, model.ArchivalDNSLookupResult{
		Answers:          aaaa,
		Engine:           ev.ResolverNetwork,
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "AAAA",
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		T:                ev.Finished.Sub(begin).Seconds(),
	})
	return
}

func (ev *FlatDNSLookupEvent) gatherA() (out []model.ArchivalDNSAnswer) {
	for _, addr := range ev.Addresses {
		if strings.Contains(addr, ":") {
			continue // it's AAAA so we need to skip it
		}
		answer := model.ArchivalDNSAnswer{AnswerType: "A"}
		asn, org, _ := geolocate.LookupASN(addr)
		answer.ASN = int64(asn)
		answer.ASOrgName = org
		answer.IPv4 = addr
		out = append(out, answer)
	}
	return
}

func (ev *FlatDNSLookupEvent) gatherAAAA() (out []model.ArchivalDNSAnswer) {
	for _, addr := range ev.Addresses {
		if !strings.Contains(addr, ":") {
			continue // it's A so we need to skip it
		}
		answer := model.ArchivalDNSAnswer{AnswerType: "AAAA"}
		asn, org, _ := geolocate.LookupASN(addr)
		answer.ASN = int64(asn)
		answer.ASOrgName = org
		answer.IPv6 = addr
		out = append(out, answer)
	}
	return
}

//
// NetworkEvents
//

// NewArchivalNetworkEventList builds a network events list in the OONI
// archival data format out of the results saved inside the trace.
func (t *Trace) NewArchivalNetworkEventList(begin time.Time) []model.ArchivalNetworkEvent {
	return NewArchivalNetworkEventList(begin, t.Network)
}

// NewArchivalNetworkEventList builds a network events list in the OONI
// archival data format out of the results saved inside the trace.
func NewArchivalNetworkEventList(begin time.Time, in []*FlatNetworkEvent) (out []model.ArchivalNetworkEvent) {
	for _, ev := range in {
		out = append(out, ev.ToArchivalNetworkEvent(begin))
	}
	return
}

// ToArchivalNetworkEvent converts a FlatNetworkEvent to ArchivalNetworkEvent.
func (ev *FlatNetworkEvent) ToArchivalNetworkEvent(begin time.Time) model.ArchivalNetworkEvent {
	return model.ArchivalNetworkEvent{
		Address:   ev.RemoteAddr,
		Failure:   ev.Failure.ToArchivalFailure(),
		NumBytes:  int64(ev.Count),
		Operation: ev.Operation,
		Proto:     string(ev.Network),
		T:         ev.Finished.Sub(begin).Seconds(),
		Tags:      nil,
	}
}

//
// TLS handshake
//

// NewArchivalTLSOrQUICHandshakeResultList builds a TLS/QUIC handshakes list in the OONI
// archival data format out of the results saved inside the trace.
func (t *Trace) NewArchivalTLSOrQUICHandshakeResultList(begin time.Time) []model.ArchivalTLSOrQUICHandshakeResult {
	return NewArchivalTLSOrQUICHandshakeResultList(begin, t.QUICTLSHandshake)
}

// NewArchivalTLSOrQUICHandshakeResultList builds a TLS/QUIC handshakes list in the OONI
// archival data format out of the results saved inside the trace.
func NewArchivalTLSOrQUICHandshakeResultList(
	begin time.Time, in []*FlatQUICTLSHandshakeEvent) (out []model.ArchivalTLSOrQUICHandshakeResult) {
	for _, ev := range in {
		out = append(out, ev.ToArchival(begin))
	}
	return
}

// ToArchival converts FlatQUICTLSHandshakeEvent to ArchivalTLSOrQUICHandshakeResult.
func (ev *FlatQUICTLSHandshakeEvent) ToArchival(begin time.Time) model.ArchivalTLSOrQUICHandshakeResult {
	return model.ArchivalTLSOrQUICHandshakeResult{
		Address:            ev.RemoteAddr,
		CipherSuite:        ev.CipherSuite,
		Failure:            ev.Failure.ToArchivalFailure(),
		NegotiatedProtocol: ev.NegotiatedProto,
		NoTLSVerify:        ev.SkipVerify,
		PeerCertificates:   ev.makePeerCerts(ev.PeerCerts),
		Proto:              string(ev.Network),
		ServerName:         ev.SNI,
		T:                  ev.Finished.Sub(begin).Seconds(),
		Tags:               nil,
		TLSVersion:         ev.TLSVersion,
	}
}

func (ev *FlatQUICTLSHandshakeEvent) makePeerCerts(in [][]byte) (out []model.ArchivalMaybeBinaryData) {
	for _, v := range in {
		out = append(out, model.ArchivalMaybeBinaryData{Value: string(v)})
	}
	return
}

//
// DNS round trip
//

// NewArchivalDNSRoundTripEventList converts the DNSRoundTripEvent list
// inside the trace to the corresponding archival format.
func (t *Trace) NewArchivalDNSRoundTripEventList(begin time.Time) []model.ArchivalDNSRoundTripEvent {
	return NewArchivalDNSRoundTripEventList(begin, t.DNSRoundTrip)
}

// NewArchivalDNSRoundTripEventList converts the DNSRoundTripEvent list
// inside the trace to the corresponding archival format.
func NewArchivalDNSRoundTripEventList(begin time.Time, in []*FlatDNSRoundTripEvent) (out []model.ArchivalDNSRoundTripEvent) {
	for _, ev := range in {
		out = append(out, *ev.ToArchival(begin))
	}
	return
}

// ToArchival converts a FlatDNSRoundTripEvent into ArchivalDNSRoundTripEvent.
func (ev *FlatDNSRoundTripEvent) ToArchival(begin time.Time) *model.ArchivalDNSRoundTripEvent {
	return &model.ArchivalDNSRoundTripEvent{
		Address:  ev.Address,
		Failure:  ev.Failure.ToArchivalFailure(),
		Finished: ev.Finished.Sub(begin).Seconds(),
		Network:  string(ev.Network),
		Query:    ev.bytesToBinaryData(ev.Query),
		Reply:    ev.bytesToBinaryData(ev.Reply),
		Started:  ev.Started.Sub(begin).Seconds(),
	}
}

func (ev *FlatDNSRoundTripEvent) bytesToBinaryData(in []byte) *model.ArchivalBinaryData {
	if len(in) < 1 {
		return nil
	}
	return &model.ArchivalBinaryData{
		Format: "base64",
		Data:   in,
	}
}
