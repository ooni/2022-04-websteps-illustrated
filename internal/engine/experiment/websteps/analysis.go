package websteps

//
// Analysis
//
// This file contains code to analyze results.
//

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
)

// Analysis contains the results of the analysis.
type Analysis struct {
	// DNS contains the DNS results analysis.
	DNS []*AnalysisDNS `json:"dns"`

	// Endpoint contains the endpoint results analysis.
	Endpoint []*AnalysisEndpoint `json:"endpoint"`
}

// We represent analysis results using an int64 bitmask. We define
// the following groups of bits within the bitmask:
//
//     0    4    8   12   16   20   24   28   32
//     +----+----+----+----+----+----+----+----+
//     |       DNS         |   TCP, TLS, QUIC  |
//     +----+----+----+----+----+----+----+----+
//     |       HTTP        |Misc|     Priv     |
//     +----+----+----+----+----+----+----+----+
//
// The DNS group is DNS related. The TCP, TLS, QUIC group is related
// to TCP, TLS, or QUIC. The HTTP group is related to HTTP.
//
// The Misc group contains miscellaneous flags.
//
// The Priv group contains implementation-reserved flags. A data
// consumer MUST ignore the reserved bits. An implementation SHOULD
// NOT clear Priv flags, which may be useful when debugging.
const (
	//
	// Group: DNS
	//
	AnalysisNXDOMAIN     = 1 << 0
	AnalysisDNSTimeout   = 1 << 1
	AnalysisBogon        = 1 << 2
	AnalysisDNSNoAnswer  = 1 << 3
	AnalysisDNSRefused   = 1 << 4
	AnalysisUnassigned5  = 1 << 5
	AnalysisDNSDiff      = 1 << 6
	AnalysisDNSServfail  = 1 << 7
	AnalysisUnassigned8  = 1 << 8
	AnalysisUnassigned9  = 1 << 9
	AnalysisUnassigned10 = 1 << 10
	AnalysisUnassigned11 = 1 << 11
	AnalysisUnassigned12 = 1 << 12
	AnalysisUnassigned13 = 1 << 13
	AnalysisUnassigned14 = 1 << 14
	AnalysisDNSOther     = 1 << 15
	//
	// Group: TCP, TLS, QUIC
	//
	AnalysisTCPTimeout    = 1 << 16
	AnalysisTCPRefused    = 1 << 17
	AnalysisQUICTimeout   = 1 << 18
	AnalysisTLSTimeout    = 1 << 19
	AnalysisTLSEOF        = 1 << 20
	AnalysisTLSReset      = 1 << 21
	AnalysisCertificate   = 1 << 22 // most likely MITM
	AnalysisUnassigned23  = 1 << 23
	AnalysisUnassigned24  = 1 << 24
	AnalysisUnassigned25  = 1 << 25
	AnalysisUnassigned26  = 1 << 26
	AnalysisUnassigned27  = 1 << 27
	AnalysisUnassigned28  = 1 << 28
	AnalysisUnassigned29  = 1 << 29
	AnalysisUnassigned30  = 1 << 30
	AnalysisEndpointOther = 1 << 31
	//
	// Group: HTTP
	//
	AnalysisUnused32           = 1 << 32
	AnalysisHTTPTimeout        = 1 << 33
	AnalysisHTTPReset          = 1 << 34
	AnalysisHTTPEOF            = 1 << 35
	AnalysisHTTPDiffStatusCode = 1 << 36
	AnalysisHTTPDiffHeaders    = 1 << 37
	AnalysisHTTPDiffTitle      = 1 << 38
	AnalysisHTTPDiffBodyLength = 1 << 39
	AnalysisUnassigned40       = 1 << 40
	AnalysisUnassigned41       = 1 << 41
	AnalysisUnassigned42       = 1 << 42
	AnalysisUnassigned43       = 1 << 43
	AnalysisUnassigned44       = 1 << 44
	AnalysisUnassigned45       = 1 << 45
	AnalysisUnassigned46       = 1 << 46
	AnalysisHTTPOther          = 1 << 47
	//
	// Group: Misc
	//
	AnalysisTHFailure = 1 << 48 // the TH failed
	AnalysisUnused49  = 1 << 49
	AnalysisUnused50  = 1 << 50
	AnalysisUnused51  = 1 << 51
	//
	// Group: Reserv
	//
	AnalysisHTTPLegitimateRedir = 1 << 52
	AnalysisDNSCanceledTimeout  = 1 << 53
	AnalysisDNSNotLying         = 1 << 54 // whether we can use IPs for TLS
	AnalysisHTTPAccessible      = 1 << 55 // no blocking and page makes sense
	AnalysisGiveUp              = 1 << 56
	AnalysisBrokenIPv6          = 1 << 57
	AnalysisProbeBug            = 1 << 58
	AnalysisInconsistent        = 1 << 59
	AnalysisConsistent          = 1 << 60
	AnalysisHTTPMaybeProxy      = 1 << 61
	AnalysisHTTPDiffBodyHash    = 1 << 62
	AnalysisUnused63            = 1 << 63
)

//
// URL
//

// aggregateFlags computes overall analysis for the SingleStepMeasurement.
func (ssm *SingleStepMeasurement) aggregateFlags() (flags int64) {
	if ssm.Analysis != nil {
		for _, score := range ssm.Analysis.DNS {
			flags |= score.Flags
		}
		for _, score := range ssm.Analysis.Endpoint {
			flags |= score.Flags
		}
	}
	return
}

//
// DNS
//

// AnalysisDNS is the analysis of an invididual query.
type AnalysisDNS struct {
	// ID is the unique ID of this analysis.
	ID int64 `json:"id"`

	// URLMeasurementID is the related URL measurement ID.
	URLMeasurementID int64 `json:"-"`

	// Ref references the measurements we used.
	Refs []int64 `json:"refs"`

	// Flags contains the analysis flags.
	Flags int64 `json:"flags"`
}

func analysisPrettyRefs(refs []int64) string {
	var out []string
	for _, e := range refs {
		out = append(out, fmt.Sprintf("#%d", e))
	}
	return strings.Join(out, ", ")
}

// Describes this analysis.
func (ad *AnalysisDNS) Describe() string {
	return fmt.Sprintf("dns analysis in #%d comparing %s",
		ad.URLMeasurementID, analysisPrettyRefs(ad.Refs))
}

// dnsAnalysis analyzes the probe's DNS lookups. This function returns
// nil when there's no DNS lookup data to analyze.
func (ssm *SingleStepMeasurement) dnsAnalysis(
	mx measurex.AbstractMeasurer, logger model.Logger) (out []*AnalysisDNS) {
	if ssm.ProbeInitial == nil {
		// should not happen in practice, just a safety net.
		return nil
	}
	var flags int64
	if ssm.TH == nil {
		flags |= AnalysisTHFailure
	}
	for _, pq := range ssm.ProbeInitial.DNS {
		switch pq.LookupType() {
		case archival.DNSLookupTypeGetaddrinfo, archival.DNSLookupTypeHTTPS:
			score := ssm.dnsSingleLookupAnalysis(mx, logger, pq)
			score.Flags |= flags
			out = append(out, score)
		default:
			// Ignore this specific lookup type
		}
	}
	return out
}

// dnsSingleLookupAnalysis analyzes a single DNS lookup.
func (ssm *SingleStepMeasurement) dnsSingleLookupAnalysis(mx measurex.AbstractMeasurer,
	logger model.Logger, pq *measurex.DNSLookupMeasurement) *AnalysisDNS {
	score := &AnalysisDNS{
		ID:               mx.NextID(),
		URLMeasurementID: pq.URLMeasurementID,
		Refs:             []int64{pq.ID},
		Flags:            0,
	}

	// Corner case: when you don't have IPv6 support, you fail with
	// "host unreachable" or "net unreachable". Because these kind of
	// errors are not _widely_ used for censorship, our heuristic
	// is that we consider these cases as IPv6 availability failures.
	switch pq.Failure() {
	case netxlite.FailureHostUnreachable,
		netxlite.FailureNetworkUnreachable:
		if pq.UsingResolverIPv6() {
			score.Flags |= AnalysisBrokenIPv6
			return score
		}
	}

	// If the domain name we're trying to resolve is an
	// IP address, which happens with, e.g., https://1.1.1.1/,
	// then the case is immediately closed.
	if net.ParseIP(pq.Domain()) != nil {
		return score
	}

	// Before bothering with checking with the test helper, let us
	// consider cases where we can validate the query result regardless
	// of whether there's a test helper response.
	if pq.Failure() == "" {
		// Countries like Iran censor returning bogon addresses.
		if ssm.dnsBogonsCheck(pq) {
			score.Flags |= AnalysisBogon
			// TODO(bassosimone): here we can double down on the bogon
			// analysis by checking for injection in dnsping.
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
		logger.Warnf("🐛 [dns] cannot find TH measurement matching #%d", pq.ID)
		return score
	}

	logger.Infof("🙌 [dns] matched probe #%d with TH #%d", pq.ID, thq.ID)

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
		logger.Warn("[dns] give up analysis because the TH failed")
		return score
	}

	// Next, there's the case where just the probe failed. This is
	// one of the most common cases of censorship.
	if failure := pq.Failure(); failure != "" {
		// A probe failure without a TH failure is unexpected.
		switch failure {
		case netxlite.FailureDNSNXDOMAINError:
			score.Flags |= AnalysisNXDOMAIN
			// TODO(bassosimone): here we can double down on the NXDOMAIN
			// analysis by checking for injection in dnsping.
		case netxlite.FailureDNSRefusedError:
			score.Flags |= AnalysisDNSRefused
		case netxlite.FailureGenericTimeoutError:
			score.Flags |= AnalysisDNSTimeout
			dnspingID, found := ssm.dnsCanCancelTimeoutFlag(pq)
			if found {
				logger.Infof("🙌 timeout in #%d for %s using %s was transient (see #%d)",
					pq.ID, pq.Domain(), pq.ResolverURL(), dnspingID)
				score.Refs = append(score.Refs, dnspingID)
				score.Flags &= ^AnalysisDNSTimeout
				score.Flags |= AnalysisDNSCanceledTimeout
			}
		case netxlite.FailureDNSNoAnswer:
			score.Flags |= AnalysisDNSNoAnswer
		case netxlite.FailureDNSServfailError:
			score.Flags |= AnalysisDNSServfail
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

// dnsCanCancelTimeoutFlag returns true if dnsping succeeded at least
// once for a query for which we faced a timeout.
//
// Return value:
//
// - ID of the dnsping measurement that allowed us to cancel the timeout;
//
// - whether we could cancel the timeout.
func (ssm *SingleStepMeasurement) dnsCanCancelTimeoutFlag(
	pq *measurex.DNSLookupMeasurement) (int64, bool) {
	if ssm.DNSPing == nil || pq.ResolverNetwork() != archival.NetworkTypeUDP {
		return 0, false
	}
	for _, ping := range ssm.DNSPing.Pings {
		const urlMeasurementID = 0 // does not matter
		fakeLookups := ping.DNSLookupMeasurementList(urlMeasurementID, pq.Domain())
		for _, e := range fakeLookups {
			if pq.Domain() != e.Domain() {
				continue
			}
			if pq.LookupType() != e.LookupType() {
				continue
			}
			if e.Failure() != "" {
				continue
			}
			// If one of the pings for the same domain and lookup
			// type succeeds, we conclude the timeout was transient
			return e.ID, true
		}
	}
	return 0, false
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
			thAddr := epnt.IPAddress()
			if thAddr == "" {
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
// returns the corresponding TH query.
//
// This algorithm runs two passes: in the first pass it tries
// to find a compatible measurement and the second pass relaxes
// the compatibility definition to be weaker.
//
// This function _expects_ the TH to pass us only lookups using
// the "https" resolver network and warns otherwise.
//
// This function _assumes_ to be passed a lookup type for
// either "https" or "getaddrinfo" and warns otherwise.
func (ssm *SingleStepMeasurement) dnsFindMatchingQuery(
	pq *measurex.DNSLookupMeasurement) (*measurex.DNSLookupMeasurement, bool) {
	if ssm.TH == nil {
		return nil, false
	}
	switch pq.LookupType() {
	case archival.DNSLookupTypeGetaddrinfo, archival.DNSLookupTypeHTTPS:
	default:
		log.Printf("[BUG] dnsFindMatchingQuery passed unexpected lookup type: %s", pq.LookupType())
		return nil, false
	}
	// first attempt: try to find a compatible measurement
	for _, thq := range ssm.TH.DNS {
		if v := thq.ResolverNetwork(); v != archival.NetworkTypeDoH {
			log.Printf("[BUG] unexpected resolver network in TH: %s", v)
		}
		if !pq.IsCompatibleWith(thq) {
			continue
		}
		return thq, true
	}
	// second attempt: try to find a weakly compatible measurement
	for _, thq := range ssm.TH.DNS {
		if v := thq.ResolverNetwork(); v != archival.NetworkTypeDoH {
			log.Printf("[BUG] unexpected resolver network in TH: %s", v)
		}
		if !pq.IsWeaklyCompatibleWith(thq) {
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
	URLMeasurementID int64 `json:"-"`

	// Ref is the ID of the lookup.
	Refs []int64 `json:"refs"`

	// Flags contains the analysis flags.
	Flags int64 `json:"flags"`

	// probe is a pointer to the probe measurement that generated
	// this AnalysisEndpoint; set for reprocessing at the end.
	probe *measurex.EndpointMeasurement `json:"-"`

	// th is like probe but for the TH
	th *measurex.EndpointMeasurement `json:"-"`
}

// Describes this analysis.
func (ad *AnalysisEndpoint) Describe() string {
	return fmt.Sprintf("endpoint analysis in #%d comparing %s",
		ad.URLMeasurementID, analysisPrettyRefs(ad.Refs))
}

// endpointAnalysis analyzes the probe's endpoint measurements. This function
// returns nil when there's no endpoint data to analyze.
func (ssm *SingleStepMeasurement) endpointAnalysis(
	mx measurex.AbstractMeasurer, logger model.Logger) (out []*AnalysisEndpoint) {
	var flags int64
	if ssm.TH == nil {
		flags |= AnalysisTHFailure
	}
	if ssm.ProbeInitial != nil {
		for _, pe := range ssm.ProbeInitial.Endpoint {
			score := ssm.endpointSingleMeasurementAnalysis(mx, logger, pe)
			score.Flags |= flags
			out = append(out, score)
		}
	}
	for _, pe := range ssm.ProbeAdditional {
		score := ssm.endpointSingleMeasurementAnalysis(mx, logger, pe)
		score.Flags |= flags
		out = append(out, score)
	}
	return out
}

// endpointSingleMeasurementAnalysis analyzes a single DNS lookup.
func (ssm *SingleStepMeasurement) endpointSingleMeasurementAnalysis(
	mx measurex.AbstractMeasurer, logger model.Logger,
	pe *measurex.EndpointMeasurement) *AnalysisEndpoint {
	score := &AnalysisEndpoint{
		ID:               mx.NextID(),
		URLMeasurementID: pe.URLMeasurementID,
		Refs:             []int64{pe.ID},
		Flags:            0,
	}

	// Corner case: when you don't have IPv6 support, you fail with
	// "host unreachable" or "net unreachable". Because these kind of
	// errors are not _widely_ used for censorship, our heuristic
	// is that we consider these cases as IPv6 availability failures.
	switch pe.Failure {
	case netxlite.FailureHostUnreachable,
		netxlite.FailureNetworkUnreachable:
		if pe.UsingAddressIPv6() {
			score.Flags |= AnalysisBrokenIPv6
			return score
		}
	}

	// If we find a bogon address, flag this but continue processing
	if addr := pe.IPAddress(); addr != "" && netxlite.IsBogon(addr) {
		score.Flags |= AnalysisBogon
		// fallthrough
	}

	// Let's now see to compare with what the TH did.
	the, found := ssm.endpointFindMatchingMeasurement(pe)
	if !found {
		// Special case: if we are using HTTPS (or HTTP3) and we
		// succeded, then we're most likely okay, modulo sanctions.
		if pe.Failure == "" && pe.Scheme() == "https" {
			score.Flags |= AnalysisHTTPAccessible
			return score
		}
		// Without having additional data we cannot really
		// continue the analysis and reach a conclusion.
		score.Flags |= AnalysisGiveUp
		logger.Warnf("🐛 [endpoint] cannot find TH measurement matching #%d", pe.ID)
		return score
	}

	logger.Infof("🙌 [endpoint] matched probe #%d with TH #%d", pe.ID, the.ID)

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
		logger.Warn("[endpoint] give up analysis because the TH failed")
		return score
	}

	// So, let's check whether just the probe failed.
	if pe.Failure != "" {
		switch pe.FailedOperation {
		case netxlite.ConnectOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisTCPTimeout
			case netxlite.FailureConnectionRefused:
				score.Flags |= AnalysisTCPRefused
			default:
				score.Flags |= AnalysisEndpointOther
			}
		case netxlite.TLSHandshakeOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisTLSTimeout
			case netxlite.FailureConnectionReset:
				score.Flags |= AnalysisTLSReset
			case netxlite.FailureSSLInvalidCertificate,
				netxlite.FailureSSLInvalidHostname,
				netxlite.FailureSSLUnknownAuthority:
				score.Flags |= AnalysisCertificate
			case netxlite.FailureEOFError:
				score.Flags |= AnalysisTLSEOF
			default:
				score.Flags |= AnalysisEndpointOther
			}
		case netxlite.QUICHandshakeOperation:
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisQUICTimeout
			case netxlite.FailureSSLInvalidCertificate,
				netxlite.FailureSSLInvalidHostname,
				netxlite.FailureSSLUnknownAuthority:
				score.Flags |= AnalysisCertificate
			default:
				score.Flags |= AnalysisEndpointOther
			}
		case netxlite.HTTPRoundTripOperation:
			// Here we need to attribute the failure to the adversary-
			// observable highest-level protocol.
			var (
				isHTTPS = pe.Scheme() == "https" && pe.Network == archival.NetworkTypeTCP
				isHTTP3 = pe.Scheme() == "https" && pe.Network == archival.NetworkTypeQUIC
				isHTTP  = pe.Scheme() == "http"
			)
			switch pe.Failure {
			case netxlite.FailureGenericTimeoutError:
				switch {
				case isHTTP:
					score.Flags |= AnalysisHTTPTimeout
				case isHTTP3:
					score.Flags |= AnalysisQUICTimeout
				case isHTTPS:
					score.Flags |= AnalysisTLSTimeout
				default:
					score.Flags |= AnalysisProbeBug // what scheme is this?!
				}
			case netxlite.FailureConnectionReset:
				switch {
				case isHTTP:
					score.Flags |= AnalysisHTTPReset
				case isHTTPS:
					score.Flags |= AnalysisTLSReset
				default:
					score.Flags |= AnalysisProbeBug // what scheme is this?!
				}
			case netxlite.FailureEOFError:
				switch {
				case isHTTP:
					score.Flags |= AnalysisHTTPEOF
				case isHTTPS:
					score.Flags |= AnalysisTLSEOF
				default:
					score.Flags |= AnalysisProbeBug // what scheme is this?!
				}
			default:
				switch {
				case isHTTP:
					score.Flags |= AnalysisHTTPOther
				case isHTTPS, isHTTP3:
					score.Flags |= AnalysisEndpointOther
				default:
					score.Flags |= AnalysisProbeBug // what scheme is this?!
				}
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
		score.Flags |= AnalysisHTTPAccessible
		return score
	}

	// Before going down the DiffHTTP rabbit hole, let's check whether this
	// request contains a legitimate redirect. We say that a redirect is
	// legitimate when it's for the same domain or for reasonable variations
	// of the original domain. While this won't cover all false positives,
	// there are plently of cases where this heuristic works.
	//
	// Why this heuristic? Mainly because the probe and the TH may see
	// differences in their redirect when using HTTP. For example, it may
	// happen that a given endpoint returns 200 for the probe and 301 or
	// 302 for the test helper. The heuristics below will flag this as
	// a DiffHTTP but actually it is not _as long as_ the 302's location
	// looks legitimate for the domain of the request URL.
	if pe.SeemsLegitimateRedirect() {
		score.Flags |= AnalysisHTTPLegitimateRedir
		return score
	}

	// We're now approaching Web Connectivity territory. A DiffHTTP indicates a
	// possible blockpage for HTTP and perhaps sanctions for HTTPS and HTTP3.
	//
	// Note that ALL measurements where we apply Web Connectivity algorithms are
	// marked for reprocessing once websteps is done. One of the actions we'll do
	// in reprocessing is spotting cases in which the probe received a 200 Ok
	// while the TH was redirected to the same resource and fetched it at a later
	// time. This condition seems like a transparent non-lying HTTP proxy.
	//
	// An example URL that exhibits this behavior is:
	// http://ajax.aspnetcdn.com/ajax/4.5.2/1/MicrosoftAjax.js
	//
	// This set of conditions is adapted from MK v0.10.11.
	flags := ssm.endpointWebConnectivityStatusCodeMatch(logger, pe, the)
	score.probe = pe // for reprocessing
	score.th = the   // ditto
	score.Flags |= flags
	if flags == 0 {
		tlshDiff, good := ssm.endpointHashingTLSHCompareBodies(pe, the)
		if good {
			// According to the TLSH paper, a diff score less than 60
			// has false positives rate of 1% in detecting possibly
			// polymorphic pieces of malware. With this score, it seems
			// we're on a reasonable territory when it boils down to
			// detect similar webpages w/o significant changes.
			//
			// See https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf
			const tlshThreshold = 60
			if tlshDiff < tlshThreshold {
				score.Flags |= AnalysisHTTPAccessible
				return score
			}
			// Fallback to the original Web Connectivity length checking algo.
			//
			// Here's why:
			//
			// The body hash is good at detecting _similar_ bodies but I have seen
			// cases (e.g., http://itafilm.tv) where the web server replies with
			// a body only consisting of a JavaScript redirect with most of the body
			// being occupied by a random base64 string.
			//
			// For this reason the DiffBodyHash flag is an internal flag and we're
			// going to rely on the original heuristics for spotting a diff.
			score.Flags |= AnalysisHTTPDiffBodyHash
		}
		flags = ssm.endpointWebConnectivityBodyLengthChecks(pe, the)
		if flags == 0 {
			score.Flags |= AnalysisHTTPAccessible
			return score
		}
		score.Flags |= flags
		flags = ssm.endpointWebConnectivityHeadersMatch(pe, the)
		if flags == 0 {
			score.Flags |= AnalysisHTTPAccessible
			return score
		}
		score.Flags |= flags
		flags := ssm.endpointWebConnectivityTitleMatch(pe, the)
		if flags == 0 {
			score.Flags |= AnalysisHTTPAccessible
			return score
		}
		score.Flags |= flags
		// fallthrough
	}
	return score
}

// endpointFindMatchingMeasurement takes in input a probe's endpoint and
// returns in output the corresponding TH endpoint measurement.
func (ssm *SingleStepMeasurement) endpointFindMatchingMeasurement(
	pe *measurex.EndpointMeasurement) (*measurex.EndpointMeasurement, bool) {
	if ssm.TH == nil {
		return nil, false
	}
	for _, the := range ssm.TH.Endpoint {
		if pe.IsAnotherInstanceOf(the) {
			return the, true
		}
	}
	return nil, false
}
