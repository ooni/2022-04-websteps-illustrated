package websteps

//
// Analysis
//
// This file contains code to analyze results.
//

import (
	"net"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
)

// We represent analysis results using an int64 bitmask. We define
// the following groups of bits within the bitmask:
//
//     0                16                   32
//     +-----------------+-------------------+
//     |    DNS (16 bit) | endpoint (16 bit) |
//     +-----------------+-------------------+
//     |   HTTP (16 bit) | reserved (16 bit) |
//     +-----------------+-------------------+
//
// Data consumers SHOULD NOT rely on the reserved bits.
const (
	AnalysisDNSNXDOMAIN        = 1 << 0
	AnalysisDNSTimeout         = 1 << 1
	AnalysisDNSBogon           = 1 << 2
	AnalysisDNSNoAnswer        = 1 << 3
	AnalysisDNSRefused         = 1 << 4
	AnalysisDNSUnassigned5     = 1 << 5
	AnalysisDNSDiff            = 1 << 6
	AnalysisDNSUnassigned7     = 1 << 7
	AnalysisDNSUnassigned8     = 1 << 8
	AnalysisDNSUnassigned9     = 1 << 9
	AnalysisDNSUnassigned10    = 1 << 10
	AnalysisDNSUnassigned11    = 1 << 11
	AnalysisDNSUnassigned12    = 1 << 12
	AnalysisDNSUnassigned13    = 1 << 13
	AnalysisDNSUnassigned14    = 1 << 14
	AnalysisDNSOther           = 1 << 15
	AnalysisEpntTCPTimeout     = 1 << 16
	AnalysisEpntTCPRefused     = 1 << 17
	AnalysisEpntQUICTimeout    = 1 << 18
	AnalysisEpntTLSTimeout     = 1 << 19
	AnalysisEpntTLSEOF         = 1 << 20
	AnalysisEpntTLSReset       = 1 << 21
	AnalysisEpntCertificate    = 1 << 22
	AnalysisEpntUnassigned23   = 1 << 23
	AnalysisEpntUnassigned24   = 1 << 24
	AnalysisEpntUnassigned25   = 1 << 25
	AnalysisEpntUnassigned26   = 1 << 26
	AnalysisEpntUnassigned27   = 1 << 27
	AnalysisEpntUnassigned28   = 1 << 28
	AnalysisEpntUnassigned29   = 1 << 29
	AnalysisEpntUnassigned30   = 1 << 30
	AnalysisEpntOther          = 1 << 31
	AnalysisHTTPUnassigned32   = 1 << 32
	AnalysisHTTPTimeout        = 1 << 33
	AnalysisHTTPReset          = 1 << 34
	AnalysisHTTPEOF            = 1 << 35
	AnalysisHTTPDiffStatusCode = 1 << 36
	AnalysisHTTPDiffHeaders    = 1 << 37
	AnalysisHTTPDiffTitle      = 1 << 38
	AnalysisHTTPDiffBodyLength = 1 << 39
	AnalysisHTTPUnassigned40   = 1 << 40
	AnalysisHTTPUnassigned41   = 1 << 41
	AnalysisHTTPUnassigned42   = 1 << 42
	AnalysisHTTPUnassigned43   = 1 << 43
	AnalysisHTTPUnassigned44   = 1 << 44
	AnalysisHTTPUnassigned45   = 1 << 45
	AnalysisHTTPUnassigned46   = 1 << 46
	AnalysisHTTPOther          = 1 << 47
	AnalysisGiveUp             = 1 << 48
	AnalysisAdditionalEpnt     = 1 << 49
	AnalysisBrokenIPv6         = 1 << 50
	AnalysisProbeBug           = 1 << 51
	AnalysisAccessible         = 1 << 52
	AnalysisInconsistent       = 1 << 53
	AnalysisConsistent         = 1 << 54
	AnalysisDNSNotLying        = 1 << 55
	AnalysisHTTPSecure         = 1 << 56
)

//
// URL
//

// AnalysisURL is the analysis of an URL measurement.
type AnalysisURL struct {
	// ID is the unique ID of this analysis.
	ID int64 `json:"id"`

	// URLMeasurementID is the related URL measurement ID.
	URLMeasurementID int64 `json:"url_measurement_id"`

	// Ref references the analyses we used.
	Refs []int64 `json:"refs"`

	// Flags contains the analysis flags.
	Flags int64 `json:"flags"`
}

//
// DNS
//

// urlAnalysis computes overall analysis for a given URL.
func (ssm *SingleStepMeasurement) urlAnalysis(
	mx *measurex.Measurer, logger model.Logger) (out *AnalysisURL) {
	out = &AnalysisURL{
		ID:               mx.NextID(),
		URLMeasurementID: ssm.ID(),
		Refs:             []int64{},
		Flags:            0,
	}
	for _, score := range ssm.Analysis.DNS {
		out.Flags |= score.Flags
		out.Refs = append(out.Refs, score.ID)
	}
	for _, score := range ssm.Analysis.Endpoint {
		out.Flags |= score.Flags
		out.Refs = append(out.Refs, score.ID)
	}
	return out
}

// AnalysisDNS is the analysis of an invididual query.
type AnalysisDNS struct {
	// ID is the unique ID of this analysis.
	ID int64 `json:"id"`

	// URLMeasurementID is the related URL measurement ID.
	URLMeasurementID int64 `json:"url_measurement_id"`

	// Ref references the measurements we used.
	Refs []int64 `json:"refs"`

	// Flags contains the analysis flags.
	Flags int64 `json:"flags"`
}

// dnsAnalysis analyzes the probe's DNS lookups. This function returns
// nil when there's no DNS lookup data to analyze.
func (ssm *SingleStepMeasurement) dnsAnalysis(
	mx *measurex.Measurer, logger model.Logger) (out []*AnalysisDNS) {
	if ssm.ProbeInitial == nil {
		// should not happen in practice, just a safety net.
		return nil
	}
	for _, pq := range ssm.ProbeInitial.DNS {
		score := ssm.dnsSingleLookupAnalysis(mx, logger, pq)
		ExplainFlagsWithLogging(logger, pq, score.Flags)
		out = append(out, score)
	}
	return out
}

// dnsSingleLookupAnalysis analyzes a single DNS lookup.
func (ssm *SingleStepMeasurement) dnsSingleLookupAnalysis(mx *measurex.Measurer,
	logger model.Logger, pq *measurex.DNSLookupMeasurement) *AnalysisDNS {
	score := &AnalysisDNS{
		ID:               mx.NextID(),
		URLMeasurementID: pq.URLMeasurementID,
		Refs:             []int64{pq.ID},
		Flags:            0,
	}

	// Corner case: when you don't have IPv6 support, you fail with
	// "host unreachable" (sometimes "net unreachable") and generally
	// the failure is super quick (sub-millisecond). We need to
	// intercept this corner case and just ignore this query.
	switch pq.Failure() {
	case netxlite.FailureHostUnreachable,
		netxlite.FailureNetworkUnreachable:
		if delta := pq.Runtime(); delta > 0 && delta < 3*time.Millisecond {
			score.Flags |= AnalysisBrokenIPv6
			return score
		}
	}

	// If the domain name we're trying to resolve is an
	// IP address, which happens with, e.g., https://1.1.1.1/,
	// then the case is immediately closed.
	if net.ParseIP(pq.Domain()) != nil {
		score.Flags |= AnalysisAccessible
		return score
	}

	// Before bothering with checking with the test helper, let us
	// consider cases where we can validate the query result regardless
	// of whether there's a test helper response.
	if pq.Failure() == "" {
		// Countries like Iran censor returning bogon addresses.
		if ssm.dnsBogonsCheck(pq) {
			score.Flags |= AnalysisDNSBogon
			return score
		}
		// If we could use any of the IP addresses returned by this query
		// for establishing TLS connections, we're ~confident that we've
		// been given legitimate IP addresses by the resolver.
		if ssm.dnsAnyIPAddrWorksWithHTTPS(pq) {
			score.Flags |= AnalysisDNSNotLying
			return score
		}
		// We cannot yet reach a conclusion, let's continue.
	}

	// Let's now see to compare with what the TH did.
	thq, found := ssm.dnsFindMatchingQuery(pq)
	if !found {
		// Without having additional data we cannot really
		// continue the analysis and reach a conclusion.
		score.Flags |= AnalysisGiveUp
		logger.Warn("[dns] give up analysis because there's no matching TH query")
		return score
	}

	score.Refs = append(score.Refs, thq.ID)

	// Next we check whether both us and the TH failed.
	if pq.Failure() != "" && thq.Failure() != "" {
		if pq.Failure() == thq.Failure() {
			score.Flags |= AnalysisConsistent
			return score
		}
		// Because the resolvers failed differently, we
		// lean towards inconclusive. There may be differences
		// in getaddrinfo implementation leading to this
		// result (see, e.g., https://github.com/ooni/probe/issues/2029).
		score.Flags |= AnalysisInconsistent
		return score
	}

	// Then there's the case where just the TH failed.
	if thq.Failure() != "" {
		// If only the TH failed, then this is also quite
		// strange/unexpected. We could dig in more but, for
		// now, let's just give up for now.
		score.Flags |= AnalysisGiveUp
		logger.Warn("[dns] give up analysis because just the TH failed")
		return score
	}

	// Next, there's the case where just the probe failed. This is
	// one of the most common cases of censorship.
	if failure := pq.Failure(); failure != "" {
		// A probe failure without a TH failure is unexpected.
		switch failure {
		case netxlite.FailureDNSNXDOMAINError:
			score.Flags |= AnalysisDNSNXDOMAIN
		case netxlite.FailureDNSRefusedError:
			score.Flags |= AnalysisDNSRefused
		case netxlite.FailureGenericTimeoutError:
			score.Flags |= AnalysisDNSTimeout
		default:
			score.Flags |= AnalysisDNSOther
		}
		return score
	}

	// So, now we're in the case in which both succeded. We know from
	// the above checks that we didn't receive any bogon and the TH could
	// not complete any HTTPS measurement with this query's results.
	if ssm.dnsWebConnectivityDNSDiff(pq, thq) {
		score.Flags |= AnalysisDNSDiff
	}

	return score
}

// dnsBogonsCheck checks whether a successful reply contains bogons.
func (ssm *SingleStepMeasurement) dnsBogonsCheck(pq *measurex.DNSLookupMeasurement) bool {
	if pq.Failure() != "" {
		// Just in case there's some bug
		return false
	}
	for _, addr := range pq.Addresses() {
		if netxlite.IsBogon(addr) {
			return true
		}
	}
	return false
}

// dnsAnyIPAddrWorksWithHTTPS checks whether the TH could use one of the
// IP addrs returned by the probe to perform any HTTPS measurement.
func (ssm *SingleStepMeasurement) dnsAnyIPAddrWorksWithHTTPS(
	pq *measurex.DNSLookupMeasurement) bool {
	if ssm.TH == nil || pq.Failure() != "" {
		// Just in case there's some bug
		return false
	}
	var count int64
	for _, prAddr := range pq.Addresses() {
		for _, epnt := range ssm.TH.Endpoint {
			thAddr, err := epnt.IPAddress()
			if err != nil {
				// This also seems a bug or an edge case
				continue
			}
			if prAddr != thAddr || epnt.Scheme() != "https" {
				// Not the droids we were looking for
				continue
			}
			if epnt.Failure != "" {
				// If at least a single IP address works we assume that
				// the DNS is not returning us lies.
				continue
			}
			count++
		}
	}
	return count > 0 // be sure we did run the loop
}

// dnsFindMatchingQuery takes in input a probe's query and
// returns in output the corresponding TH query.
func (ssm *SingleStepMeasurement) dnsFindMatchingQuery(
	pq *measurex.DNSLookupMeasurement) (*measurex.DNSLookupMeasurement, bool) {
	if ssm.TH == nil {
		return nil, false
	}
	for _, thq := range ssm.TH.DNS {
		if pq.Domain() != thq.Domain() {
			continue
		}
		if pq.LookupType() != thq.LookupType() {
			continue
		}
		return thq, true
	}
	return nil, false
}

//
// Endpoint
//

// AnalysisEndpoint is the analysis of an individual endpoint.
type AnalysisEndpoint struct {
	// ID is the unique ID of this analysis.
	ID int64 `json:"id"`

	// URLMeasurementID is the related URL measurement ID.
	URLMeasurementID int64 `json:"url_measurement_id"`

	// Ref is the ID of the lookup.
	Refs []int64 `json:"refs"`

	// Flags contains the analysis flags.
	Flags int64 `json:"flags"`
}

// endpointAnalysis analyzes the probe's endpoint measurements. This function
// returns nil when there's no endpoint data to analyze.
func (ssm *SingleStepMeasurement) endpointAnalysis(
	mx *measurex.Measurer, logger model.Logger) (out []*AnalysisEndpoint) {
	if ssm.ProbeInitial != nil {
		for _, pe := range ssm.ProbeInitial.Endpoint {
			score := ssm.endpointSingleMeasurementAnalysis(mx, logger, pe, 0)
			ExplainFlagsWithLogging(logger, pe, score.Flags)
			out = append(out, score)
		}
	}
	for _, pe := range ssm.ProbeAdditional {
		score := ssm.endpointSingleMeasurementAnalysis(
			mx, logger, pe, AnalysisAdditionalEpnt)
		ExplainFlagsWithLogging(logger, pe, score.Flags)
		out = append(out, score)
	}
	return out
}

// endpointSingleMeasurementAnalysis analyzes a single DNS lookup.
func (ssm *SingleStepMeasurement) endpointSingleMeasurementAnalysis(mx *measurex.Measurer,
	logger model.Logger, pe *measurex.EndpointMeasurement, flags int64) *AnalysisEndpoint {
	score := &AnalysisEndpoint{
		ID:               mx.NextID(),
		URLMeasurementID: pe.URLMeasurementID,
		Refs:             []int64{pe.ID},
		Flags:            0,
	}

	// Honour flags passed by the caller.
	score.Flags |= flags

	// Corner case: when you don't have IPv6 support, you fail with
	// "host unreachable" (sometimes "net unreachable") and generally
	// the failure is super quick (sub-millisecond). We need to
	// intercept this corner case and just ignore this measurement.
	switch pe.Failure {
	case netxlite.FailureHostUnreachable,
		netxlite.FailureNetworkUnreachable:
		if delta := pe.TCPQUICConnectRuntime(); delta > 0 && delta < 3*time.Millisecond {
			score.Flags |= AnalysisBrokenIPv6
			return score
		}
	}

	// If we find a bogon address, flag this but continue processing
	if addr, err := pe.IPAddress(); err == nil && netxlite.IsBogon(addr) {
		score.Flags |= AnalysisDNSBogon
		// fallthrough
	}

	// Take note of whether we're using HTTP or HTTPS here.
	if pe.Scheme() == "https" {
		score.Flags |= AnalysisHTTPSecure
	}

	// Let's now see to compare with what the TH did.
	the, found := ssm.endpointFindMatchingMeasurement(pe)
	if !found {
		// Special case: if we are using HTTPS (or HTTP3) and we
		// succeded, then we're most likely okay, modulo sanctions.
		if pe.Failure == "" && pe.Scheme() == "https" {
			return score
		}
		// Without having additional data we cannot really
		// continue the analysis and reach a conclusion.
		score.Flags |= AnalysisGiveUp
		logger.Warn(
			"[endpoint] give up analysis because we cannot find a corresponding measurement")
		return score
	}

	score.Refs = append(score.Refs, the.ID)

	// Next, check whether both us and the TH failed.
	if pe.Failure != "" && the.Failure != "" {
		if pe.Failure == the.Failure &&
			pe.FailedOperation == the.FailedOperation {
			// Both have observed the same failure in the
			// same failed operation.
			score.Flags |= AnalysisConsistent
			return score
		}
		// If they failed differently, for now we're going
		// to consider this case as "meh".
		score.Flags |= AnalysisInconsistent
		return score
	}

	// Then, there's the case where just the TH failed.
	if the.Failure != "" {
		// It's strange/unexpected but there may be some bug in
		// the backend or some other backend-side issue, so we're
		// just going to give up making a sense of the result.
		score.Flags |= AnalysisGiveUp
		logger.Warn("[endpoint] give up analysis because just the TH failed")
		return score
	}

	// So, let's check whether just the probe failed.
	if pe.Failure != "" {
		switch pe.FailedOperation {
		case netxlite.ConnectOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisEpntTCPTimeout
			case netxlite.FailureConnectionRefused:
				score.Flags |= AnalysisEpntTCPRefused
			default:
				score.Flags |= AnalysisEpntOther
			}
		case netxlite.TLSHandshakeOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisEpntTLSTimeout
			case netxlite.FailureConnectionReset:
				score.Flags |= AnalysisEpntTLSReset
			case netxlite.FailureSSLInvalidCertificate,
				netxlite.FailureSSLInvalidHostname,
				netxlite.FailureSSLUnknownAuthority:
				score.Flags |= AnalysisEpntCertificate
			default:
				score.Flags |= AnalysisEpntOther
			}
		case netxlite.QUICHandshakeOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisEpntQUICTimeout
			case netxlite.FailureSSLInvalidCertificate,
				netxlite.FailureSSLInvalidHostname,
				netxlite.FailureSSLUnknownAuthority:
				score.Flags |= AnalysisEpntCertificate
			default:
				score.Flags |= AnalysisEpntOther
			}
		case netxlite.HTTPRoundTripOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisHTTPTimeout
			case netxlite.FailureConnectionReset:
				score.Flags |= AnalysisHTTPReset
			default:
				score.Flags |= AnalysisHTTPOther
			}
		default:
			// We should not have a different failed operation, so
			// it's clearly a bug if we end up here
			score.Flags |= AnalysisProbeBug
		}
		return score
	}

	// We're not prepared yet to fully handle server-side blocking in
	// the probe, so stop here in case of HTTPS.
	if pe.Scheme() == "https" {
		return score
	}

	// We're now approaching Web Connectivity territory. A DiffHTTP indicates a
	// possible blockpage for HTTP and perhaps sanctions for HTTPS and HTTP3.
	//
	// This set of conditions is adapted from MK v0.10.11.
	flags = ssm.endpointWebConnectivityStatusCodeMatch(pe, the)
	score.Flags |= flags
	if flags == 0 {
		flags = ssm.endpointWebConnectivityBodyLengthChecks(pe, the)
		if flags == 0 {
			return score
		}
		score.Flags |= flags
		flags = ssm.endpointWebConnectivityHeadersMatch(pe, the)
		if flags == 0 {
			return score
		}
		score.Flags |= flags
		flags := ssm.endpointWebConnectivityTitleMatch(pe, the)
		if flags == 0 {
			return score
		}
		score.Flags |= flags
		// fallthrough
	}
	return score
}

// endpointFindMatchingMeasurement takes in input a probe's endpoin and
// returns in output the corresponding TH endpoint measurement.
func (ssm *SingleStepMeasurement) endpointFindMatchingMeasurement(
	pe *measurex.EndpointMeasurement) (*measurex.EndpointMeasurement, bool) {
	if ssm.TH == nil {
		return nil, false
	}
	for _, the := range ssm.TH.Endpoint {
		p, _ := pe.Summary()
		t, _ := the.Summary()
		if p != t {
			continue
		}
		return the, true
	}
	return nil, false
}
