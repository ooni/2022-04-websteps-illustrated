package archival

//
// Code to convert to the archival JSON format.
//

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/engine/geolocate"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/miekg/dns"
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
		Started: ev.Started.Sub(begin).Seconds(),
		T:       ev.Finished.Sub(begin).Seconds(),
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
func (t *Trace) NewArchivalHTTPRequestResultList(
	begin time.Time, bodyFlags int64) []model.ArchivalHTTPRequestResult {
	return NewArchivalHTTPRequestResultList(begin, t.HTTPRoundTrip, bodyFlags)
}

// NewArchivalHTTPRequestResultList builds an HTTP requests list in the OONI
// archival data format out of the results saved inside the trace.
//
// This function will sort the emitted list of requests such that the last
// request that happened in time is the first one to be emitted. If the
// measurement code performs related requests sequentially (which is a kinda a
// given because you cannot follow a redirect before reading the previous request),
// then the result is sorted how the OONI pipeline expects it to be.
func NewArchivalHTTPRequestResultList(begin time.Time,
	in []*FlatHTTPRoundTripEvent, bodyFlags int64) (out []model.ArchivalHTTPRequestResult) {
	for _, ev := range in {
		out = append(out, ev.ToArchival(begin, bodyFlags))
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
func (ev *FlatHTTPRoundTripEvent) ToArchival(begin time.Time,
	bodyFlags int64) model.ArchivalHTTPRequestResult {
	return model.ArchivalHTTPRequestResult{
		Failure: ev.Failure.ToArchivalFailure(),
		Request: model.ArchivalHTTPRequest{
			Body:            model.ArchivalMaybeBinaryData{},
			BodyIsTruncated: false,
			HeadersList:     NewHTTPHeadersList(ev.RequestHeaders),
			Headers:         ev.newHTTPHeadersMap(ev.RequestHeaders),
			Method:          ev.Method,
			Tor:             model.ArchivalHTTPTor{},
			Transport:       ev.Transport,
			URL:             ev.URL,
		},
		Response: model.ArchivalHTTPResponse{
			Body: model.ArchivalHTTPBodyOrTLSH{
				Body: model.ArchivalMaybeBinaryData{
					Value: ev.ResponseBody,
				},
				Flags: bodyFlags,
				TLSH:  ev.ResponseBodyTLSH,
			},
			BodyLength:      ev.ResponseBodyLength,
			BodyIsTruncated: ev.ResponseBodyIsTruncated,
			BodyTLSH:        ev.ResponseBodyTLSH,
			Code:            ev.StatusCode,
			HeadersList:     NewHTTPHeadersList(ev.ResponseHeaders),
			Headers:         ev.newHTTPHeadersMap(ev.ResponseHeaders),
			Locations:       ev.ResponseHeaders.Values("Location"), // safe with nil headers
		},
		Started: ev.Started.Sub(begin).Seconds(),
		T:       ev.Finished.Sub(begin).Seconds(),
	}
}

// NewHTTPHeadersList converts a list HTTP headers to a list of archival HTTP headers.
func NewHTTPHeadersList(source http.Header) (out []model.ArchivalHTTPHeader) {
	for key, values := range source {
		for _, value := range values {
			out = append(out, model.ArchivalHTTPHeader{
				Key: key,
				Value: model.ArchivalMaybeBinaryData{
					Value: []byte(value),
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
			out[key] = model.ArchivalMaybeBinaryData{Value: []byte(value)}
		}
	}
	return
}

//
// DNS
//

// NewArchivalDNSLookupResultList builds a DNS lookups list in the OONI
// archival data format out of the results saved inside the trace.
//
// Deprecated: new code should obtain the archival data format from the
// DNS round trip rather than from the DNS lookup result.
func (t *Trace) NewArchivalDNSLookupResultList(begin time.Time) []model.ArchivalDNSLookupResult {
	return NewArchivalDNSLookupResultList(begin, t.DNSLookup)
}

// NewArchivalDNSLookupResultList builds a DNS lookups list in the OONI
// archival data format out of the results saved inside the trace.
//
// Deprecated: new code should obtain the archival data format from the
// DNS round trip rather than from the DNS lookup result.
func NewArchivalDNSLookupResultList(begin time.Time, in []*FlatDNSLookupEvent) (out []model.ArchivalDNSLookupResult) {
	for _, ev := range in {
		out = append(out, ev.ToArchival(begin)...)
	}
	return
}

// ToArchival converts a FlatDNSLookupEvent to []ArchivalDNSLookupResult.
//
// Deprecated: new code should obtain the archival data format from the
// DNS round trip rather than from the DNS lookup result.
func (ev *FlatDNSLookupEvent) ToArchival(begin time.Time) []model.ArchivalDNSLookupResult {
	switch ev.LookupType {
	case DNSLookupTypeHTTPS:
		return ev.toArchivalHTTPS(begin)
	case DNSLookupTypeGetaddrinfo:
		return ev.toArchivalGetaddrinfo(begin)
	case DNSLookupTypeNS:
		return ev.toArchivalNS(begin)
	default:
		logcat.Bugf("ToArchivalDNSLookupResultList: unhandled record: %+v", ev)
		return []model.ArchivalDNSLookupResult{}
	}
}

func (ev *FlatDNSLookupEvent) toArchivalHTTPS(begin time.Time) (out []model.ArchivalDNSLookupResult) {
	out = append(out, model.ArchivalDNSLookupResult{
		Answers:          ev.gatherHTTPS(),
		Engine:           string(ev.ResolverNetwork),
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "HTTPS",
		RawQuery:         nil,
		RawReply:         nil,
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		Started:          ev.Started.Sub(begin).Seconds(),
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
		ipv6, err := netxlite.IsIPv6(addr)
		if err != nil {
			continue
		}
		if ipv6 {
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

func (ev *FlatDNSLookupEvent) toArchivalNS(begin time.Time) (out []model.ArchivalDNSLookupResult) {
	out = append(out, model.ArchivalDNSLookupResult{
		Answers:          ev.gatherNS(),
		Engine:           string(ev.ResolverNetwork),
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "NS",
		RawQuery:         nil,
		RawReply:         nil,
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		Started:          ev.Started.Sub(begin).Seconds(),
		T:                ev.Finished.Sub(begin).Seconds(),
	})
	return
}

func (ev *FlatDNSLookupEvent) gatherNS() (out []model.ArchivalDNSAnswer) {
	for _, e := range ev.NS {
		out = append(out, model.ArchivalDNSAnswer{
			ALPN:       "",
			ASN:        0,
			ASOrgName:  "",
			AnswerType: "NS",
			Hostname:   "",
			IPv4:       "",
			IPv6:       "",
			NS:         e,
			TTL:        nil,
		})
	}
	return
}

func (ev *FlatDNSLookupEvent) toArchivalGetaddrinfo(begin time.Time) (out []model.ArchivalDNSLookupResult) {
	out = append(out, model.ArchivalDNSLookupResult{
		Answers:          ev.gatherA(),
		Engine:           string(ev.ResolverNetwork),
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "A",
		RawQuery:         nil,
		RawReply:         nil,
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		Started:          ev.Started.Sub(begin).Seconds(),
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
		Engine:           string(ev.ResolverNetwork),
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         ev.Domain,
		QueryType:        "AAAA",
		RawQuery:         nil,
		RawReply:         nil,
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		Started:          ev.Started.Sub(begin).Seconds(),
		T:                ev.Finished.Sub(begin).Seconds(),
	})
	return
}

func (ev *FlatDNSLookupEvent) gatherA() (out []model.ArchivalDNSAnswer) {
	for _, addr := range ev.Addresses {
		if ipv6, err := netxlite.IsIPv6(addr); err != nil || ipv6 {
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
		if ipv6, err := netxlite.IsIPv6(addr); err != nil || !ipv6 {
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
		Started:   ev.Started.Sub(begin).Seconds(),
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
		Started:            ev.Started.Sub(begin).Seconds(),
		T:                  ev.Finished.Sub(begin).Seconds(),
		Tags:               nil,
		TLSVersion:         ev.TLSVersion,
	}
}

func (ev *FlatQUICTLSHandshakeEvent) makePeerCerts(in [][]byte) (out []model.ArchivalMaybeBinaryData) {
	for _, v := range in {
		out = append(out, model.ArchivalMaybeBinaryData{Value: v})
	}
	return
}

//
// DNS round trip
//

// NewArchivalDNSRoundTripEventList converts the DNSRoundTripEvent list
// inside the trace to the corresponding archival format.
func (t *Trace) NewArchivalDNSRoundTripEventList(begin time.Time) []model.ArchivalDNSLookupResult {
	return NewArchivalDNSRoundTripEventList(begin, t.DNSRoundTrip)
}

// NewArchivalDNSRoundTripEventList converts the DNSRoundTripEvent list
// inside the trace to the corresponding archival format.
func NewArchivalDNSRoundTripEventList(begin time.Time, in []*FlatDNSRoundTripEvent) (out []model.ArchivalDNSLookupResult) {
	for _, ev := range in {
		out = append(out, *ev.ToArchival(begin))
	}
	return
}

// ToArchival converts a FlatDNSRoundTripEvent into ArchivalDNSRoundTripEvent.
func (ev *FlatDNSRoundTripEvent) ToArchival(begin time.Time) *model.ArchivalDNSLookupResult {
	out := &model.ArchivalDNSLookupResult{
		Answers:          []model.ArchivalDNSAnswer{}, // later
		Engine:           string(ev.ResolverNetwork),
		Failure:          ev.Failure.ToArchivalFailure(),
		Hostname:         "", // later
		QueryType:        "", // later
		RawQuery:         ev.bytesToBinaryData(ev.Query),
		RawReply:         ev.bytesToBinaryData(ev.Reply),
		ResolverHostname: nil, // legacy
		ResolverPort:     nil, // legacy
		ResolverAddress:  ev.ResolverAddress,
		Started:          ev.Started.Sub(begin).Seconds(),
		T:                ev.Finished.Sub(begin).Seconds(),
	}
	ev.fillHostnameAndQueryType(out)
	ev.fillAnswers(out)
	return out
}

func (ev *FlatDNSRoundTripEvent) fillHostnameAndQueryType(out *model.ArchivalDNSLookupResult) {
	query := &dns.Msg{}
	if err := query.Unpack(ev.Query); err != nil {
		return
	}
	if len(query.Question) != 1 {
		return
	}
	q0 := query.Question[0]
	hostname := q0.Name
	if len(hostname) > 0 && strings.HasSuffix(hostname, ".") {
		hostname = hostname[:len(hostname)-1]
	}
	out.Hostname = hostname
	switch q0.Qtype {
	case dns.TypeHTTPS:
		out.QueryType = "HTTPS"
	case dns.TypeA:
		out.QueryType = "A"
	case dns.TypeAAAA:
		out.QueryType = "AAAA"
	case dns.TypeNS:
		out.QueryType = "NS"
	case dns.TypeCNAME:
		out.QueryType = "CNAME"
	case dns.TypeANY:
		out.QueryType = "ANY"
	case dns.TypePTR:
		out.QueryType = "PTR"
	default:
		logcat.Bugf("fillHostnameAndQueryType: unhandled query type: %d", q0.Qtype)
	}
}

func (ev *FlatDNSRoundTripEvent) fillAnswers(out *model.ArchivalDNSLookupResult) {
	reply := &dns.Msg{}
	if err := reply.Unpack(ev.Reply); err != nil {
		return
	}
	if len(reply.Answer) < 1 {
		return
	}
	for _, answer := range reply.Answer {
		switch v := answer.(type) {
		case *dns.HTTPS:
			// TODO(bassosimone): properly decode HTTPS replies
			logcat.Bugf("decoding of HTTPSSvc replies is not implemented")
		case *dns.A:
			out.Answers = append(out.Answers, model.ArchivalDNSAnswer{
				ALPN:       "",
				ASN:        0,
				ASOrgName:  "",
				AnswerType: "A",
				Hostname:   "",
				IPv4:       v.A.String(),
				IPv6:       "",
				NS:         "",
				TTL:        ev.ttl(v.Hdr.Ttl),
			})
		case *dns.AAAA:
			out.Answers = append(out.Answers, model.ArchivalDNSAnswer{
				ALPN:       "",
				ASN:        0,
				ASOrgName:  "",
				AnswerType: "AAAA",
				Hostname:   "",
				IPv4:       v.AAAA.String(),
				IPv6:       "",
				NS:         "",
				TTL:        ev.ttl(v.Hdr.Ttl),
			})
		case *dns.NS:
			out.Answers = append(out.Answers, model.ArchivalDNSAnswer{
				ALPN:       "",
				ASN:        0,
				ASOrgName:  "",
				AnswerType: "NS",
				Hostname:   "",
				IPv4:       "",
				IPv6:       "",
				NS:         v.Ns,
				TTL:        ev.ttl(v.Hdr.Ttl),
			})
		case *dns.CNAME:
			out.Answers = append(out.Answers, model.ArchivalDNSAnswer{
				ALPN:       "",
				ASN:        0,
				ASOrgName:  "",
				AnswerType: "CNAME",
				Hostname:   v.Target,
				IPv4:       "",
				IPv6:       "",
				NS:         "",
				TTL:        ev.ttl(v.Hdr.Ttl),
			})
		case *dns.PTR:
			out.Answers = append(out.Answers, model.ArchivalDNSAnswer{
				ALPN:       "",
				ASN:        0,
				ASOrgName:  "",
				AnswerType: "PTR",
				Hostname:   v.Ptr, // ooniprobe-legacy probably did this
				IPv4:       "",
				IPv6:       "",
				NS:         "",
				TTL:        ev.ttl(v.Hdr.Ttl),
			})
		default:
			logcat.Bugf("fillAnswers: unhandled record type %T", answer)
		}
	}
}

func (ev *FlatDNSRoundTripEvent) ttl(value uint32) (out *uint32) {
	if ev.ResolverNetwork != "system" {
		out = &value
	}
	return
}

func (ev *FlatDNSRoundTripEvent) bytesToBinaryData(in []byte) *model.ArchivalBinaryData {
	if len(in) < 1 || ev.ResolverNetwork == "system" {
		return nil
	}
	return &model.ArchivalBinaryData{
		Format: "base64",
		Data:   in,
	}
}
