package websteps

//
// Analysis endpoint
//
// This file contains endpoint analysis.
//

import (
	"fmt"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
)

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
}

// Describes this analysis.
func (ad *AnalysisEndpoint) Describe() string {
	return fmt.Sprintf("endpoint analysis #%d for %s", ad.ID, analysisPrettyRefs(ad.Refs))
}

// endpointAnalysis analyzes the probe's endpoint measurements. This function
// returns nil when there's no endpoint data to analyze.
func (ssm *SingleStepMeasurement) endpointAnalysis(mx measurex.AbstractMeasurer) (out []*AnalysisEndpoint) {
	logcat.Substep("analyzing endpoint measurements results")
	if ssm.TH != nil {
		if ssm.ProbeInitial != nil {
			for _, pe := range ssm.ProbeInitial.Endpoint {
				logcat.Inspectf("inspecting %s", pe.Describe())
				out = append(out, analyzeSingleEndpointMeasurement(mx, pe, ssm.TH.Endpoint))
			}
		}
		for _, pe := range ssm.ProbeAdditional {
			logcat.Inspectf("inspecting %s", pe.Describe())
			out = append(out, analyzeSingleEndpointMeasurement(mx, pe, ssm.TH.Endpoint))
		}
	}
	return endpointAnalysisRemoveUnflaggedResults(out)
}

// endpointAnalysisRemoveUnflaggedResults takes in input a set of analysis results and returns
// in output another list without any result containing no flags.
func endpointAnalysisRemoveUnflaggedResults(in []*AnalysisEndpoint) (out []*AnalysisEndpoint) {
	for _, e := range in {
		if e.Flags != 0 {
			out = append(out, e)
		}
	}
	return
}

// analyzeSingleEndpointMeasurement analyzes a single endpoint measurement.
func analyzeSingleEndpointMeasurement(
	mx measurex.AbstractMeasurer, epnt *measurex.EndpointMeasurement,
	otherEpnts []*measurex.EndpointMeasurement) *AnalysisEndpoint {

	// Let's start by creating the score
	score := &AnalysisEndpoint{
		ID:               mx.NextID(),
		URLMeasurementID: epnt.URLMeasurementID,
		Refs:             []int64{epnt.ID},
		Flags:            0,
	}

	// Corner case: when you don't have IPv6 support, you fail with
	// "host unreachable" or "net unreachable". Because these kind of
	// errors are not _widely_ used for censorship, our heuristic
	// is that we consider these cases as IPv6 availability failures.
	switch epnt.Failure {
	case netxlite.FailureHostUnreachable,
		netxlite.FailureNetworkUnreachable:
		if epnt.UsingAddressIPv6() {
			logcat.Infof("[#%d] ignoring #%d because it fails due to missing IPv6 support", score.ID, epnt.ID)
			return score
		}
	}

	// If we find a bogon address, then it's clearly an anomaly
	if addr := epnt.IPAddress(); addr != "" && netxlite.IsBogon(addr) {
		logcat.Confirmedf("[#%d] #%d is confirmed anomaly because it contains a bogon", score.ID, epnt.ID)
		score.Flags |= AnalysisBogon
		return score
	}

	// Special case: if we are using HTTPS (or HTTP3) and we
	// succeded, then we're most likely okay, modulo sanctions.
	if epnt.Failure == "" && epnt.Scheme() == "https" {
		logcat.Celebratef(
			"[#%d] #%d is accessible because it works with HTTPS for the probe",
			score.ID, epnt.ID)
		return score
	}

	// Let's now try to find a matching measurement.
	otherEpnt, found := analysisEndpointFindMatchingMeasurement(score.ID, epnt, otherEpnts, 0)
	if !found {
		analysisEndpointFindMatchingMeasurement(score.ID, epnt, otherEpnts, analysisLookupDebug)
		logcat.Bugf("[#%d] cannot find matching measurement for #%d: %s", score.ID, epnt.ID, epnt.Summary())
		score.Flags |= AnalysisInconclusive
		return score
	}

	score.Refs = append(score.Refs, otherEpnt.ID)

	// Next, check whether both the experiment and the control failed.
	if epnt.Failure != "" && otherEpnt.Failure != "" {
		if epnt.Failure == otherEpnt.Failure &&
			epnt.FailedOperation == otherEpnt.FailedOperation {
			logcat.Celebratef("[#%d] #%d is good because also #%d fails with %s",
				score.ID, epnt.ID, otherEpnt.ID, epnt.Failure)
			return score
		}
		// If they failed differently, for now we're going
		// to consider this case as "meh".
		logcat.Shrugf("[#%d] #%d, which fails with %s, is inconclusive because #%d fails with %s",
			score.ID, epnt.ID, epnt.Failure, otherEpnt.ID, otherEpnt.Failure)
		score.Flags |= AnalysisInconclusive
		return score
	}

	// Then, there's the case where just the "control" failed
	if otherEpnt.Failure != "" {
		logcat.Shrugf("[#%d] #%d succeded and #%d failed: inconclusive", score.ID, epnt.ID, otherEpnt.ID)
		score.Flags |= AnalysisInconclusive
		return score
	}

	// So, let's check whether just the "experiment" failed.
	if epnt.Failure != "" {
		switch epnt.FailedOperation {
		case netxlite.ConnectOperation:
			switch epnt.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisTCPTimeout
			case netxlite.FailureConnectionRefused:
				score.Flags |= AnalysisTCPRefused
			default:
				score.Flags |= AnalysisInconclusive
			}
		case netxlite.TLSHandshakeOperation:
			switch epnt.Failure {
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
				score.Flags |= AnalysisInconclusive
			}
		case netxlite.QUICHandshakeOperation:
			switch epnt.Failure {
			case netxlite.FailureGenericTimeoutError:
				score.Flags |= AnalysisQUICTimeout
			case netxlite.FailureSSLInvalidCertificate,
				netxlite.FailureSSLInvalidHostname,
				netxlite.FailureSSLUnknownAuthority:
				score.Flags |= AnalysisCertificate
			default:
				score.Flags |= AnalysisInconclusive
			}
		case netxlite.HTTPRoundTripOperation:
			// Here we need to attribute the failure to the adversary-
			// observable highest-level protocol.
			var (
				isHTTPS = epnt.Scheme() == "https" && epnt.Network == archival.NetworkTypeTCP
				isHTTP3 = epnt.Scheme() == "https" && epnt.Network == archival.NetworkTypeQUIC
				isHTTP  = epnt.Scheme() == "http"
			)
			switch epnt.Failure {
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
					score.Flags |= AnalysisInconclusive
				case isHTTPS, isHTTP3:
					score.Flags |= AnalysisInconclusive
				default:
					score.Flags |= AnalysisProbeBug // what scheme is this?!
				}
			}
		default:
			// We should not have a different failed operation, so
			// it's clearly a bug if we end up here
			score.Flags |= AnalysisProbeBug
		}
		ExplainFlagsWithLogging(score, score.Flags)
		return score
	}

	// Perform HTTP diff analysis
	webFlags := analysisWebHTTPDiff(score.ID, epnt, otherEpnt)

	// Deal with possible false positives caused by redirects
	if (webFlags & (AnalysisHTTPDiff | AnalysisHTTPDiffStatusCode)) != 0 {
		candidate, found := analysisRedirectTransparentProxyCheck(
			score.ID, epnt, otherEpnt, otherEpnts)
		if found {
			score.Refs = append(score.Refs, candidate)
			score.Flags |= AnalysisHTTPDiffTransparentProxy
			return score
		}
		if analysisRedirectLegitimateRedirect(score.ID, epnt) {
			score.Flags |= AnalysisHTTPDiffLegitimateRedirect
			return score
		}
	}

	score.Flags |= webFlags
	return score
}

// analysisEndpointFindMatchingMeasurement takes in input a probe's endpoint and
// returns in output the corresponding TH endpoint measurement.
func analysisEndpointFindMatchingMeasurement(scoreID int64, epnt *measurex.EndpointMeasurement,
	otherEpnts []*measurex.EndpointMeasurement, flags int64) (*measurex.EndpointMeasurement, bool) {
	if (flags & analysisLookupDebug) != 0 {
		logcat.Bugf("[#%d] trying to find a compatible match for #%d", scoreID, epnt.ID)
		logcat.Bugf("[#%d] this is otherEpnts: %+v", scoreID, otherEpnts)
	}
	for _, otherEpnt := range otherEpnts {
		if (flags & analysisLookupDebug) != 0 {
			logcat.Bugf("[#%d] checking whether #%d is another instance of #%d...", scoreID, otherEpnt.ID, epnt.ID)
		}
		if epnt.IsAnotherInstanceOf(otherEpnt) {
			return otherEpnt, true
		}
		if (flags & analysisLookupDebug) != 0 {
			logcat.Bugf("[#%d] candidate %s does not match %s", scoreID,
				otherEpnt.Summary(), epnt.Summary())
		}
	}
	return nil, false
}
