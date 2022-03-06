package websteps

//
// Explain
//
// Code to explain measurements to users.
//

import (
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// explainFlagsToVerb returns the right verb depending on inconclusive
func explainFlagsToVerb(flags int64) string {
	if (flags & AnalysisFlagInconclusive) != 0 {
		return "seems"
	}
	return "is"
}

// explainFlagsToFailureTags returns a string describing the failures we saw.
func explainFlagsToFailureTags(flags int64) string {
	var out []string
	if (flags & AnalysisFlagFailureDNS) != 0 {
		out = append(out, "#dns_failure")
	}
	if (flags & AnalysisFlagFailureTCP) != 0 {
		out = append(out, "#tcp_failure")
	}
	if (flags & AnalysisFlagFailureQUIC) != 0 {
		out = append(out, "#quic_failure")
	}
	if (flags & AnalysisFlagFailureHTTP) != 0 {
		out = append(out, "#http_failure")
	}
	if (flags & AnalysisFlagDiffDNS) != 0 {
		out = append(out, "#dns_diff")
	}
	if (flags & AnalysisFlagDNSBogon) != 0 {
		out = append(out, "#dns_bogon")
	}
	if (flags & AnalysisFlagHTTPDiffBodyLength) != 0 {
		out = append(out, "#http_diff_body")
	}
	if (flags & AnalysisFlagHTTPDiffHeaders) != 0 {
		out = append(out, "#http_diff_headers")
	}
	if (flags & AnalysisFlagHTTPDiffStatusCode) != 0 {
		out = append(out, "#http_diff_status_code")
	}
	if (flags & AnalysisFlagHTTPDiffTitle) != 0 {
		out = append(out, "#http_diff_title")
	}
	return strings.Join(out, " ")
}

// Explainable is something we can explain.
type Explainable interface {
	// Describe returns a description of the explainable.
	Describe() string
}

// ExplainFailureFlags explains the DNS flags assigned ta measurement.
func ExplainFailureFlags(logger model.Logger, ei Explainable, flags int64) {
	if (flags & AnalysisFlagUnexpected) != 0 {
		verb := explainFlagsToVerb(flags)
		failures := explainFlagsToFailureTags(flags)
		logger.Infof("❗ %s %s blocked (%s)", ei.Describe(), verb, failures)
		return
	}
	if (flags & AnalysisFlagAccessible) != 0 {
		verb := explainFlagsToVerb(flags)
		logger.Infof("🙌️️ %s %s accessible", ei.Describe(), verb)
		return
	}
	if (flags & AnalysisFlagGiveUp) != 0 {
		logger.Infof("🤷 give up analysis for %s", ei.Describe())
		return
	}
}
