package websteps

//
// Analysis DNS
//
// This file contains DNS analysis.
//

import (
	"fmt"
	"net"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/dnsping"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
)

// AnalysisDNS is the analysis of an individual lookup.
type AnalysisDNS struct {
	// ID is the unique ID of this analysis.
	ID int64 `json:"id"`

	// URLMeasurementID is the related URL measurement ID.
	URLMeasurementID int64 `json:"-"`

	// Ref references the measurements we used. The first ref is the
	// measurement we're describing and the other refs instead are
	// the measurement(s) we use as the "control".
	Refs []int64 `json:"refs"`

	// Flags contains the analysis flags.
	Flags int64 `json:"flags"`
}

// Describes this analysis.
func (ad *AnalysisDNS) Describe() string {
	return fmt.Sprintf("dns analysis #%d for %s", ad.ID, analysisPrettyRefs(ad.Refs))
}

// dnsAnalysis analyzes the probe's DNS lookups. The analysis works as follows: we
// compare each probe lookup with the matching TH lookup.
//
// The return value is a list of analysis statements, one for each comparison. This
// function returns nil when there's no DNS lookup data to analyze.
func (ssm *SingleStepMeasurement) dnsAnalysis(mx measurex.AbstractMeasurer) (out []*AnalysisDNS) {
	logcat.Substep("analyzing DNS measurements results")
	if ssm.ProbeInitial == nil {
		logcat.Bug("dnsAnalysis passed ssm with nil ProbeInitial")
		return nil
	}

	// 1. build the list of lists of endpoints to use to confirm DNS lookups
	var endpoints [][]*measurex.EndpointMeasurement
	endpoints = append(endpoints, ssm.ProbeInitial.Endpoint)
	if ssm.TH != nil {
		endpoints = append(endpoints, ssm.TH.Endpoint)
	}
	endpoints = append(endpoints, ssm.ProbeAdditional)

	// 2. gather dnsping information (if available)
	var pings []*dnsping.SinglePingResult
	if ssm.DNSPing != nil {
		pings = ssm.DNSPing.Pings
	}

	// 3. gather TH DNS measurements results (if available)
	var thDNS []*measurex.DNSLookupMeasurement
	if ssm.TH != nil {
		thDNS = ssm.TH.DNS
	}

	// 4. pit each probe lookup against the TH lookups.
	for _, d := range ssm.ProbeInitial.DNS {
		logcat.Inspectf("inspecting %s", d.Describe())
		out = append(out, analyzeSingleDNSLookup(mx, d, thDNS, pings, endpoints...))
	}

	// 8. zap unflagged results and return
	return dnsAnalysisRemoveUnflaggedResults(out)
}

// dnsAnalysisRemoveUnflaggedResults takes in input a set of analysis results and returns
// in output another list without any result containing no flags.
func dnsAnalysisRemoveUnflaggedResults(in []*AnalysisDNS) (out []*AnalysisDNS) {
	for _, e := range in {
		if e.Flags != 0 {
			out = append(out, e)
		}
	}
	return
}

// analyzeSingleDNSLookup takes in input a given DNS lookup measurement and returns a score
// for such a measurement by comparing it to other lookup measurements. This function uses the
// given abstract measurer to assign an ID to the returned score. This function also uses a
// list of endpoint measurements to validate the IP addresses inside the lookup. This function
// also uses the list of pings to cancel timeouts and perform cross checks.
func analyzeSingleDNSLookup(mx measurex.AbstractMeasurer, lookup *measurex.DNSLookupMeasurement,
	otherLookups []*measurex.DNSLookupMeasurement, pings []*dnsping.SinglePingResult,
	epnts ...[]*measurex.EndpointMeasurement) *AnalysisDNS {

	// Let's start by creating the score
	score := &AnalysisDNS{
		ID:               mx.NextID(),
		URLMeasurementID: lookup.URLMeasurementID,
		Refs:             []int64{lookup.ID},
		Flags:            0,
	}

	logcat.Infof("[#%d] analyzing #%d: %s", score.ID, lookup.ID, lookup.Summary())

	if lookup.ID <= 0 {
		logcat.Bugf("[#%d] lookup with ID <= 0: %+v", score.ID, lookup)
		score.Flags |= AnalysisProbeBug
		return score
	}

	// Ensure that we're using a getaddrinfo or HTTPS-kind lookup. All the other kind
	// of lookups are not actionable by this analysis function.
	switch v := lookup.LookupType(); v {
	case archival.DNSLookupTypeGetaddrinfo, archival.DNSLookupTypeHTTPS:
	default:
		logcat.Bugf("[#%d] analyzeSingleDNSLookup passed unexpected lookup type: %s", lookup.ID, v)
		score.Flags |= AnalysisProbeBug
		return score
	}

	// If the domain name we're trying to resolve is an IP address, which happens
	// with URLs such as, e.g., https://1.1.1.1/, then there's nothing to do.
	if net.ParseIP(lookup.Domain()) != nil {
		logcat.Celebratef(
			"[#%d] #%d is OK because it refers to an IP address", score.ID, lookup.ID)
		return score
	}

	// Corner case: when you don't have IPv6 support, you fail with
	// "host unreachable" or "net unreachable". Because these kind of
	// errors are not _widely_ used for censorship, our heuristic
	// is that we consider these cases as IPv6 availability failures.
	switch lookup.Failure() {
	case netxlite.FailureHostUnreachable,
		netxlite.FailureNetworkUnreachable:
		if lookup.UsingResolverIPv6() {
			logcat.Infof(
				"[#%d] ignoring #%d because it fails due to missing IPv6 support",
				score.ID, lookup.ID)
			return score
		}
	}

	// Before entering into any comparison with other measurements, let us
	// consider cases where we can emit a verdict right away.
	if lookup.Failure() == "" {
		// Countries like Iran censor returning bogon addresses.
		if dnsAnalysisBogonsCheck(lookup) {
			// TODO(bassosimone): here we can double down on the bogon
			// analysis by checking for injection in dnsping.
			logcat.Confirmedf(
				"[#%d] #%d is confirmed anomaly because it contains a bogon", score.ID, lookup.ID)
			score.Flags |= AnalysisBogon
			return score
		}
		// If HTTPS works with addresses in this lookup, we are most likely good.
		if dnsAnalysisHTTPSCheck(lookup, epnts...) {
			logcat.Celebratef(
				"[#%d] #%d is OK: at least one of its addresses (%s) work with HTTPS for the probe or the TH",
				score.ID, lookup.ID, strings.Join(lookup.Addresses(), ", "))
			return score
		}
		// We cannot yet reach a conclusion, let's continue.
	}

	// To continue, we need to find a matching measurement in the other set of lookups.
	peerLookup, found := dnsAnalysisFindMatchingLookup(score.ID, lookup, otherLookups, 0)
	if !found {
		dnsAnalysisFindMatchingLookup(score.ID, lookup, otherLookups, analysisLookupDebug)
		logcat.Bugf(
			"[#%d] cannot find matching measurement for #%d: %s",
			score.ID, lookup.ID, lookup.Summary())
		score.Flags |= AnalysisInconclusive
		return score
	}

	score.Refs = append(score.Refs, peerLookup.ID)

	// The next step is to check whether both lookup and peerLookup failed.
	if lookup.Failure() != "" && peerLookup.Failure() != "" {
		if lookup.Failure() == peerLookup.Failure() {
			logcat.Celebratef("[#%d] #%d is expected because also #%d fails with %s",
				score.ID, lookup.ID, peerLookup.ID, lookup.Failure())
			return score
		}
		// Because the resolvers failed differently, we
		// lean towards inconclusive. There may be differences
		// in getaddrinfo implementation leading to this
		// result (see, e.g., https://github.com/ooni/probe/issues/2029).
		logcat.Shrugf("[#%d] #%d, which fails with %s, is inconclusive because #%d fails with %s",
			score.ID, lookup.ID, lookup.Failure(), peerLookup.ID, peerLookup.Failure())
		score.Flags |= AnalysisInconclusive
		return score
	}

	// If just the peerLookup failed, we need other means to determine
	// whether this lookup is good that go beyond comparison.
	if peerLookup.Failure() != "" {
		logcat.Shrugf("[#%d] #%d succeded and #%d failed: inconclusive",
			score.ID, lookup.ID, peerLookup.ID)
		score.Flags |= AnalysisInconclusive
		return score
	}

	// Now there is the case where only the lookup we're examinging failed.
	if failure := lookup.Failure(); failure != "" {
		switch failure {
		case netxlite.FailureDNSNXDOMAINError:
			// TODO(bassosimone): here we can double down on the NXDOMAIN
			// analysis by checking for injection in dnsping.
			logcat.Confirmedf("[#%d] #%d succeeds and #%d fails with NXDOMAIN",
				score.ID, peerLookup.ID, lookup.ID)
			score.Flags |= AnalysisNXDOMAIN
		case netxlite.FailureDNSRefusedError:
			logcat.Confirmedf("[#%d] #%d succeeds and #%d fails with Refused",
				score.ID, peerLookup.ID, lookup.ID)
			score.Flags |= AnalysisDNSRefused
		case netxlite.FailureGenericTimeoutError:
			flags, pingID := dnsAnalysisDoubleCheckTimeout(score.ID, lookup, peerLookup, pings)
			score.Flags |= flags
			score.Refs = append(score.Refs, pingID...)
		case netxlite.FailureDNSNoAnswer:
			logcat.Confirmedf("[#%d] #%d succeeds and #%d fails with no_answer",
				score.ID, peerLookup.ID, lookup.ID)
			score.Flags |= AnalysisDNSNoAnswer
		case netxlite.FailureDNSServfailError:
			logcat.Confirmedf("[#%d] #%d succeeds and #%d fails with Servfail",
				score.ID, peerLookup.ID, lookup.ID)
			score.Flags |= AnalysisDNSServfail
		default:
			logcat.Infof(
				"[#%d] #%d succeeds and #%d fails with %s (which is an umapped error)",
				score.ID, peerLookup.ID, lookup.ID)
			score.Flags |= AnalysisInconclusive
		}
		return score
	}

	// Perform DNS diff analysis
	score.Flags |= analysisDNSDiffCheck(score.ID, lookup, peerLookup, otherLookups, epnts...)
	return score
}

// dnsAnalysisBogonsCheck checks whether a successful reply contains bogons.
func dnsAnalysisBogonsCheck(lookup *measurex.DNSLookupMeasurement) bool {
	for _, addr := range lookup.Addresses() {
		if netxlite.IsBogon(addr) {
			return true
		}
	}
	return false
}

// dnsAnalysisHTTPSCheck returns true when at least one IP address in
// the given lookup worked with HTTPS for one of the endpoints.
func dnsAnalysisHTTPSCheck(
	lookup *measurex.DNSLookupMeasurement, epnts ...[]*measurex.EndpointMeasurement) bool {
	return analysisAnySuccessfulEndpointForSchemeAndAddresses(
		epnts, "https", lookup.Addresses()...)
}

// dnsAnalysisFindMatchingLookup searches in the given list of lookups
// for a lookup comparable with the one provided in input.
func dnsAnalysisFindMatchingLookup(
	scoreID int64, lookup *measurex.DNSLookupMeasurement,
	otherLookups []*measurex.DNSLookupMeasurement,
	flags int64) (*measurex.DNSLookupMeasurement, bool) {
	// first attempt: try to find a compatible measurement (preferred)
	if (flags & analysisLookupDebug) != 0 {
		logcat.Bugf("[#%d] trying to find a compatible match for #%d", scoreID, lookup.ID)
		logcat.Bugf("[#%d] this is otherLookups: %+v", scoreID, otherLookups)
	}
	for _, peerLookup := range otherLookups {
		if (flags & analysisLookupDebug) != 0 {
			logcat.Bugf("[#%d] checking whether #%d is compatible with #%d...",
				scoreID, peerLookup.ID, lookup.ID)
		}
		if !lookup.IsCompatibleWith(peerLookup) {
			if (flags & analysisLookupDebug) != 0 {
				logcat.Bugf("[#%d] #%d is not compatible with #%d",
					scoreID, lookup.ID, peerLookup.ID)
			}
			continue
		}
		return peerLookup, true
	}
	// second attempt: try to find a weakly compatible measurement (fallback)
	if (flags & analysisLookupDebug) != 0 {
		logcat.Bugf("[#%d] trying to find a weakly-compatible match for #%d", scoreID, lookup.ID)
		logcat.Bugf("[#%d] this is otherLookups: %+v", scoreID, otherLookups)
	}
	for _, peerLookup := range otherLookups {
		if (flags & analysisLookupDebug) != 0 {
			logcat.Bugf("[#%d] checking whether #%d is weakly compatible with #%d...",
				scoreID, peerLookup.ID, lookup.ID)
		}
		if !lookup.IsWeaklyCompatibleWith(peerLookup) {
			if (flags & analysisLookupDebug) != 0 {
				logcat.Bugf("[#%d] #%d is not weakly compatible with #%d",
					scoreID, lookup.ID, peerLookup.ID)
			}
			continue
		}
		return peerLookup, true
	}
	return nil, false
}

// dnsAnalysisDoubleCheckTimeout determines whether the timeout in lookup was
// transient or further confirmed by dnsping. This function will also emit log messages
// explaining our analysis, so the caller doesn't need to do that.
func dnsAnalysisDoubleCheckTimeout(scoreID int64,
	lookup, peerLookup *measurex.DNSLookupMeasurement,
	pings []*dnsping.SinglePingResult) (flags int64, pingID []int64) {
	// Note that we can only cancel timeouts during UDP lookups
	if lookup.ResolverNetwork() == archival.NetworkTypeUDP {
		for _, ping := range pings {
			const urlMeasurementID = 0 // does not matter
			fakeLookups := ping.DNSLookupMeasurementList(urlMeasurementID, lookup.Domain())
			for _, e := range fakeLookups {
				if lookup.Domain() != e.Domain() {
					continue
				}
				if lookup.LookupType() != e.LookupType() {
					continue
				}
				if e.Failure() != "" {
					continue
				}
				logcat.Celebratef("[#%d] #%d succeeds and #%d fails with timeout (but %d %s)",
					scoreID, peerLookup.ID, lookup.ID, e.ID, "shows the timeout was transient")
				return 0, []int64{e.ID}
			}
		}
	}
	logcat.Unexpectedf("[#%d] #%d succeeds and #%d fails with timeout",
		scoreID, peerLookup.ID, lookup.ID)
	return AnalysisDNSTimeout, nil
}
