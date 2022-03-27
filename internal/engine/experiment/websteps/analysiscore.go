package websteps

//
// Analysis core
//
// This file contains core analysis functionality.
//

import (
	"fmt"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/engine/geolocate"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// Analysis contains the results of the analysis.
type Analysis struct {
	// DNS contains the DNS results analysis.
	DNS []*AnalysisDNS `json:"dns"`

	// Endpoint contains the endpoint results analysis.
	Endpoint []*AnalysisEndpoint `json:"endpoint"`

	// TH contains the TH results analysis.
	TH []*AnalysisEndpoint `json:"th"`
}

// We represent analysis results using an int64 bitmask. We define
// the following groups of bits within the bitmask:
//
//     0    4    8   12   16   20   24   28   32
//     +----+----+----+----+----+----+----+----+
//     |            Failure          |   HTTP  |
//     +----+----+----+----+----+----+----+----+
//     |                Reserved               |
//     +----+----+----+----+----+----+----+----+
//     32  36   40   44   48   52   56   60   64
//
// The failure flags indicate censorship conditions we detected. The
// HTTP flags provide further details regarding #httpDiff like results.
//
// All the other flags are reserved for future. Consumers of the data
// format should completely ignore all the reserved flags.
const (
	//
	// Failure
	//
	AnalysisNXDOMAIN     = 1 << 0
	AnalysisDNSTimeout   = 1 << 1
	AnalysisBogon        = 1 << 2
	AnalysisDNSNoAnswer  = 1 << 3
	AnalysisDNSRefused   = 1 << 4
	AnalysisDNSDiff      = 1 << 5
	AnalysisDNSServfail  = 1 << 6
	AnalysisTCPTimeout   = 1 << 7
	AnalysisTCPRefused   = 1 << 8
	AnalysisQUICTimeout  = 1 << 9
	AnalysisTLSTimeout   = 1 << 10
	AnalysisTLSEOF       = 1 << 11
	AnalysisTLSReset     = 1 << 12
	AnalysisCertificate  = 1 << 13
	AnalysisHTTPDiff     = 1 << 14
	AnalysisHTTPTimeout  = 1 << 15
	AnalysisHTTPReset    = 1 << 16
	AnalysisHTTPEOF      = 1 << 17
	AnalysisInconclusive = 1 << 18
	AnalysisProbeBug     = 1 << 19

	//
	// HTTP
	//
	AnalysisHTTPDiffStatusCode         = 1 << 24
	AnalysisHTTPDiffTitle              = 1 << 25
	AnalysisHTTPDiffHeaders            = 1 << 26
	AnalysisHTTPDiffBodyLength         = 1 << 27
	AnalysisHTTPDiffLegitimateRedirect = 1 << 28
	AnalysisHTTPDiffTransparentProxy   = 1 << 29
)

// AnalysisFlagsPublicMask is a mask to only keep public flags.
const AnalysisFlagsPublicMask = (1 << 32) - 1

// analysisClearInternalFlags clears internal flags from DNS and endpoint results. Note
// that this function will modify IN PLACE the content of ssm.Analysis.
func (ssm *SingleStepMeasurement) analysisClearInternalFlags() {
	if ssm.Analysis != nil {
		for _, d := range ssm.Analysis.DNS {
			d.Flags &= AnalysisFlagsPublicMask
		}
		for _, e := range ssm.Analysis.Endpoint {
			e.Flags &= AnalysisFlagsPublicMask
		}
		for _, e := range ssm.Analysis.TH {
			e.Flags &= AnalysisFlagsPublicMask
		}
	}
}

// aggregateFlags computes overall analysis for the SingleStepMeasurement.
func (ssm *SingleStepMeasurement) aggregateFlags() (flags int64) {
	if ssm.Analysis != nil {
		for _, score := range ssm.Analysis.DNS {
			flags |= score.Flags
		}
		for _, score := range ssm.Analysis.Endpoint {
			flags |= score.Flags
		}
		for _, score := range ssm.Analysis.TH {
			flags |= score.Flags
		}
	}
	return
}

const (
	// analysisLookupDebug indicates that we want the analysis code to emit
	// information when searching for a matching measurement.
	analysisLookupDebug = 1 << iota
)

// analysisPrettyRefs prettyprints a list of refs.
func analysisPrettyRefs(refs []int64) string {
	var out []string
	for _, e := range refs {
		out = append(out, fmt.Sprintf("#%d", e))
	}
	return strings.Join(out, ", ")
}

// analysisAnySuccessfulEndpointForSchemeAndAddresses processes a list of lists
// of endpoints and returns whether any of them:
//
// 1. uses the desired scheme, and
//
// 2. is successful, and
//
// 3. uses one of the provided addresses.
func analysisAnySuccessfulEndpointForSchemeAndAddresses(
	input [][]*measurex.EndpointMeasurement, scheme string, addresses ...string) bool {
	for _, epnts := range input {
		for _, epnt := range epnts {
			epntAddr := epnt.IPAddress()
			if epntAddr == "" {
				logcat.Bugf("empty address returned by #%d", epnt.ID)
				continue
			}
			if epnt.Failure != "" || epnt.Scheme() != scheme {
				continue
			}
			for _, addr := range addresses {
				if epntAddr == addr {
					return true
				}
			}
		}
	}
	return false
}

// analysisMapAddrToASN maps an IP address to an ASN number. In cae
// of failure, this function returns zero.
func analysisMapAddrToASN(addr string) uint {
	asn, _, _ := geolocate.LookupASN(addr)
	return asn
}

// we use these flags to classify who did see what
const (
	analysisInMeasurement = 1 << 0
	analysisInControl     = 1 << 1
	analysisInBoth        = analysisInMeasurement | analysisInControl
)
