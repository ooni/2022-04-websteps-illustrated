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
//     +-----------------+-------------------+
//     | common (24 bit) | protocol (40 bit) |
//     +-----------------+-------------------+
//     ^                                     ^
//    LSB                                   MSB
//
// The common bits are common to DNS and endpoint measurements, as
// their name implies. The protocol bits are specific to whether
// we're looking at a DNS or endpoint measurements.
//
// Common bits
//
// The following diagram shows the first 24 bits. Each field in
// this diagram is one bit wide. The names of the fields are same
// as in the codebase except the AnalysisFlag prefix is missing.
//
//     0             1            2              3             4
//     +-------------+------------+--------------+-------------+
//     | GiveUP      | Unexpected | Inconclusive | FailureDNS  |
//     +-------------+------------+--------------+-------------+
//     | FailureTCP  | FailureTLS | FailureQUIC  | FailureHTTP |
//     +-------------+------------+--------------+-------------+
//     | DiffHTTP    | DiffDNS    | Accessible   | ProbeBug    |
//     +-------------+------------+--------------+-------------+
//
// Where:
//
// - GiveUP means we're not able to continue the analysis because
// we're missing required data to reach a conclusion.
//
// - Unexpected means we did not expect what we are observing to
// happen (e.g., given the TH measurement).
//
// - Inconclusive means that we're seeing an anomaly that could
// potentially also be explained by bad network conditions.
//
// - DNSFailure means that a DNS lookup operation failed.
//
// - TCPFailure means that TCP connect failed.
//
// - TLSFailure means that the TLS handshake failed.
//
// - QUICFailure means that the QUIC handshake failed.
//
// - HTTPFailure is a failure when performing an HTTP request
// using one of HTTP, HTTPS, and HTTP3.
//
// - HTTPDiff means that there is a difference between what we've
// seen in the TH and what we've seen in the probe in terms of
// status code, headers, title, or body length.
//
// - Accessible means that a resource seems accessible.
//
// - ProbeBug means we found an "impossible" result meaning that
// most likely there's a bug in ooniprobe.
//
// We generally want to expose to uses (either via CLI messages or
// using visual flags) unexpected and/or unexplained failures.
//
// If a failure is explained (e.g., TCP connect failed for an IPv6
// address in a way that seems you like you don't have actually
// working IPv6 support) we don't want to mention it.
//
// The inconclusive flag coupled with a failure makes the failure
// itself a bit less strong. A common case if when there is a
// timeout. In principle, you may loose some packets. These cases
// could be investigated by running follow-up measurements.
//
// The accessible flag is set when we did not see failures. It may
// also be coupled with inconclusive when we do not have strong
// guarantees that we're talking to the right server.
//
// Protocol bits
//
// We document them briefly near each definition.
const (
	AnalysisFlagGiveUp             = 1 << 0  // cannot reach a conclusion
	AnalysisFlagUnexpected         = 1 << 1  // unexpected error
	AnalysisFlagInconclusive       = 1 << 2  // may also be connectivity issues
	AnalysisFlagFailureDNS         = 1 << 3  // failure in DNS lookup
	AnalysisFlagFailureTCP         = 1 << 4  // failure in TCP connect
	AnalysisFlagFailureTLS         = 1 << 5  // failure in TLS handshake
	AnalysisFlagFailureQUIC        = 1 << 6  // failure in QUIC handshake
	AnalysisFlagFailureHTTP        = 1 << 7  // failure during HTTP round trip
	AnalysisFlagDiffHTTP           = 1 << 8  // HTTP responses are a bit different
	AnalysisFlagDiffDNS            = 1 << 9  // DNS responses are a bit different
	AnalysisFlagAccessible         = 1 << 10 // we get some kind of response
	AnalysisFlagProbeBug           = 1 << 11 // we think there's a probe/th bug
	AnalysisFlagDNSBogon           = 1 << 24 // there is a bogon address
	AnalysisFlagDNSValidViaHTTPS   = 1 << 25 // we can use this IP with HTTPS
	AnalysisFlagDNSNXDOMAIN        = 1 << 26 // DNS NXDOMAIN failure
	AnalysisFlagDNSNoAnswer        = 1 << 27 // DNS no answer failure
	AnalysisFlagDNSRefused         = 1 << 28 // DNS refused failure
	AnalysisFlagTimeout            = 1 << 29 // we saw a timeout (maybe retry?)
	AnalysisFlagOtherError         = 1 << 30 // we've not mapped this error in flags
	AnalysisFlagEndpointHTTPS      = 1 << 31 // this endpoint works with https
	AnalysisFlagEndpointAdditional = 1 << 32 // this endpoint was discovered via the TH
	AnalysisFlagConnectionReset    = 1 << 33 // we saw a connection reset (follow up?)
	AnalysisFlagHTTPDiffBodyLength = 1 << 34 // body length differs
	AnalysisFlagHTTPDiffStatusCode = 1 << 35 // the status code differs
	AnalysisFlagHTTPDiffHeaders    = 1 << 36 // we have different headers
	AnalysisFlagHTTPDiffTitle      = 1 << 37 // titles do not match
	AnalysisFlagIPv6NotWorking     = 1 << 38 // IPv6 is not working
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
		ExplainFailureFlags(logger, pq, score.Flags)
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
		if delta := pq.Runtime(); delta > 0 && delta < time.Millisecond {
			score.Flags |= AnalysisFlagIPv6NotWorking
			return score
		}
	}

	// If the domain name we're trying to solve is an IP
	// address, which happens with, e.g., https://1.1.1.1/,
	// then the case is immediately closed.
	if net.ParseIP(pq.Domain()) != nil {
		score.Flags |= AnalysisFlagAccessible
		return score
	}

	// Let's now determine whether this result contains a DNS
	// failure or whether the DNS server is accessible.
	if pq.Failure() == "" {
		score.Flags |= AnalysisFlagAccessible
	} else {
		score.Flags |= AnalysisFlagFailureDNS
	}

	// Before bothering with checking with the test helper, let us
	// consider cases where we can validate the query result regardless
	// of whether there's a test helper response.
	if pq.Failure() == "" {
		// Countries like Iran censor returning bogon addresses. A
		// bogon for a publicly accessible website is very suspicious
		// so, we're going to flag it as an expected failure.
		if ssm.dnsBogonsCheck(pq) {
			score.Flags |= AnalysisFlagUnexpected | AnalysisFlagDNSBogon
			return score
		}
		// If we could use any of the IP addresses returned by this query
		// for establishing TLS connections, we're ~confident that we've
		// been given legitimate IP addresses by the resolver.
		if ssm.dnsAnyIPAddrWorksWithHTTPS(pq) {
			score.Flags |= AnalysisFlagAccessible | AnalysisFlagDNSValidViaHTTPS
			return score
		}
		// We cannot yet reach a conclusion, let's continue.
	}

	// Let's now see to compare with what the TH did.
	thq, found := ssm.dnsFindMatchingQuery(pq)
	if !found {
		// Without having additional data we cannot really
		// continue the analysis and reach a conclusion.
		score.Flags |= AnalysisFlagGiveUp
		logger.Warn("[dns] give up analysis because there's no matching TH query")
		return score
	}

	score.Refs = append(score.Refs, thq.ID)

	// Next we check whether both us and the TH failed.
	if pq.Failure() != "" && thq.Failure() != "" {
		if pq.Failure() == thq.Failure() {
			// If both the probe and the TH failed with the same failure
			// we can say that this result is expected. Because we have
			// set the DNS failure flag before, here we need to take
			// it back otherwise this result will be seen as an anomaly.
			score.Flags &= ^AnalysisFlagFailureDNS
			switch pq.Failure() {
			case netxlite.FailureDNSNXDOMAINError:
				score.Flags |= AnalysisFlagDNSNXDOMAIN
			case netxlite.FailureDNSNoAnswer:
				score.Flags |= AnalysisFlagDNSNoAnswer
			}
			return score
		}
		// Because the resolvers failed differently, we
		// lean towards inconclusive. There may be differences
		// in getaddrinfo implementation leading to this
		// result (see, e.g., https://github.com/ooni/probe/issues/2029).
		score.Flags |= AnalysisFlagInconclusive
		return score
	}

	// Then there's the case where just the TH failed.
	if thq.Failure() != "" {
		// If only the TH failed, then this is also quite
		// strange/unexpected. We could dig in more but, for
		// now, let's just give up for now.
		score.Flags |= AnalysisFlagGiveUp
		logger.Warn("[dns] give up analysis because just the TH failed")
		return score
	}

	// Next, there's the case where just the probe failed. This is
	// one of the most common cases of censorship.
	if failure := pq.Failure(); failure != "" {
		// A probe failure without a TH failure is unexpected.
		score.Flags |= AnalysisFlagUnexpected
		switch failure {
		case netxlite.FailureDNSNXDOMAINError:
			score.Flags |= AnalysisFlagDNSNXDOMAIN
		case netxlite.FailureDNSRefusedError:
			score.Flags |= AnalysisFlagDNSRefused
		case netxlite.FailureGenericTimeoutError:
			// Timeouts are less conclusive than more hard errors and
			// here it would actually be smart to just retry.
			score.Flags |= AnalysisFlagInconclusive | AnalysisFlagTimeout
		default:
			score.Flags |= AnalysisFlagInconclusive | AnalysisFlagOtherError
		}
		return score
	}

	// So, now we're in the case in which both succeded. We know from
	// the above checks that we didn't receive any bogon and the TH could
	// not complete any HTTPS measurement with this query's results.
	//
	// Because this algorithm is an heuristic, we cannot say _for sure_
	// that its result is correct (also because the ANS database may
	// for example be a bit old), so we're going to flag as inconclusive.
	//
	// TODO(bassosimone): double check that the following is exactly the
	// same algorithm implemented by Web Connectivity.
	score.Flags |= ssm.dnsWebConnectivityDNSDiff(pq, thq)
	score.Flags |= AnalysisFlagInconclusive

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
	var flags int64
	if ssm.ProbeInitial != nil {
		for _, pe := range ssm.ProbeInitial.Endpoint {
			score := ssm.endpointSingleMeasurementAnalysis(mx, logger, pe, flags)
			ExplainFailureFlags(logger, pe, score.Flags)
			out = append(out, score)
		}
	}
	flags |= AnalysisFlagEndpointAdditional
	for _, pe := range ssm.ProbeAdditional {
		score := ssm.endpointSingleMeasurementAnalysis(mx, logger, pe, flags)
		ExplainFailureFlags(logger, pe, score.Flags)
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
		if delta := pe.TCPQUICConnectRuntime(); delta > 0 && delta < time.Millisecond {
			score.Flags |= AnalysisFlagIPv6NotWorking
			return score
		}
	}

	// Start with setting failure or accessible.
	if pe.Failure != "" {
		switch pe.FailedOperation {
		case netxlite.ConnectOperation:
			score.Flags |= AnalysisFlagFailureTCP
		case netxlite.TLSHandshakeOperation:
			score.Flags |= AnalysisFlagFailureTLS
		case netxlite.QUICHandshakeOperation:
			score.Flags |= AnalysisFlagFailureQUIC
		case netxlite.HTTPRoundTripOperation:
			score.Flags |= AnalysisFlagFailureHTTP
		default:
			// This should not happen. If this happens we have
			// nonetheless then it's a bug in the probe.
			score.Flags |= AnalysisFlagProbeBug
			return score
		}
	} else {
		score.Flags |= AnalysisFlagAccessible
	}

	// Let's now see to compare with what the TH did.
	the, found := ssm.endpointFindMatchingMeasurement(pe)
	if !found {
		// Special case: if we are using HTTPS (or HTTP3) and we
		// succeded, we're going to consider this as a success even
		// if it's a bit inconclusive because we cannot hunt for
		// sanctions (e.g., 403 Forbidden to Iranian users).
		if pe.Failure == "" && pe.Scheme() == "https" {
			score.Flags |= AnalysisFlagEndpointHTTPS | AnalysisFlagInconclusive
			return score
		}
		// Special case: the TH will not follow bogon addresses, so
		// when following a bogon we'll only have probe data.
		//
		// TODO(bassosimone): as discussed with @hellais, we should
		// consider whether moving this check earlier.
		if addr, err := pe.IPAddress(); err == nil && netxlite.IsBogon(addr) {
			score.Flags &= ^AnalysisFlagInconclusive // a bogon is very conclusive
			score.Flags |= AnalysisFlagDNSBogon | AnalysisFlagUnexpected
			return score
		}
		// Without having additional data we cannot really
		// continue the analysis and reach a conclusion.
		score.Flags |= AnalysisFlagGiveUp
		logger.Warn("[endpoint] give up analysis because we cannot find a corresponding measurement")
		return score
	}

	score.Refs = append(score.Refs, the.ID)

	// Next, check whether both us and the TH failed.
	if pe.Failure != "" && the.Failure != "" {
		if pe.Failure == the.Failure &&
			pe.FailedOperation == the.FailedOperation {
			// Both have observed the same failure in the
			// same failed operation. We are witnessing an
			// expected failure, so no need to set bits.
			return score
		}
		// If they failed differently, for now we're going
		// to consider this case as inconclusive.
		score.Flags |= AnalysisFlagInconclusive
		return score
	}

	// Then, there's the case where just the TH failed.
	if the.Failure != "" {
		// It's strange/unexpected but there may be some bug in
		// the backend or some other backend-side issue, so we're
		// just going to give up making a sense of this result.
		score.Flags |= AnalysisFlagGiveUp
		logger.Warn("[endpoint] give up analysis because just the TH failed")
		return score
	}

	// So, let's check whether just the probe failed.
	if failure := pe.Failure; failure != "" {
		// This is certainly unexpected
		score.Flags |= AnalysisFlagUnexpected
		// Let's also flag cases in which we're a bit less certain
		// and/or cases where we may want to run follow-ups.
		switch failure {
		case netxlite.FailureConnectionReset:
			score.Flags |= AnalysisFlagConnectionReset
		case netxlite.FailureGenericTimeoutError:
			score.Flags |= AnalysisFlagTimeout | AnalysisFlagInconclusive
		default:
			score.Flags |= AnalysisFlagOtherError | AnalysisFlagInconclusive
		}
		return score
	}

	// We're now approaching Web Connectivity territory. A DiffHTTP indicates a
	// possible blockpage for HTTP and perhaps sanctions for HTTPS and HTTP3.
	//
	// These are heuristics and by definition they are inconclusive with HTTP
	// but they are much more conclusive for HTTPS.
	//
	// TODO(bassosimone): double check that the following is exactly the
	// same algorithm implemented by Web Connectivity. I am not sure about
	// this because I think in Web Connectivity we check whether at least
	// one of them matches. Here, instead, we just test for each
	// condition independently of the others.
	var httpDiff int64
	httpDiff |= ssm.endpointWebConnectivityBodyLengthChecks(pe, the)
	httpDiff |= ssm.endpointWebConnectivityStatusCodeMatch(pe, the)
	httpDiff |= ssm.endpointWebConnectivityHeadersMatch(pe, the)
	httpDiff |= ssm.endpointWebConnectivityTitleMatch(pe, the)
	if httpDiff != 0 || pe.Scheme() != "https" {
		score.Flags |= AnalysisFlagInconclusive
	}
	score.Flags |= httpDiff

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
