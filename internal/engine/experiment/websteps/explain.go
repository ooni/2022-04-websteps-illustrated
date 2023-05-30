package websteps

//
// Explain
//
// Code to explain measurements to users.
//

import (
	"strings"

	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
)

// AnalysisDescription maps an analysis flag to information useful
// to describe the same flag in a human readable way.
type AnalysisDescription struct {
	// Flag is the flag value.
	Flag int64

	// Hashtag is the related hashtag.
	Hashtag string

	// Severity is the related emoji.
	Severity int64
}

// analysisDescriptions contains all the analysis flags descriptions.
var analysisDescriptions = []*AnalysisDescription{{
	Flag:     AnalysisNXDOMAIN,
	Hashtag:  "#nxdomain",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisDNSTimeout,
	Hashtag:  "#dnsTimeout",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisBogon,
	Hashtag:  "#bogon",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisDNSNoAnswer,
	Hashtag:  "#dnsNoAnswer",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisDNSRefused,
	Hashtag:  "#dnsRefused",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisDNSDiff,
	Hashtag:  "#dnsDiff",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisDNSServfail,
	Hashtag:  "#dnsServfail",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisTCPTimeout,
	Hashtag:  "#tcpTimeout",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisTCPRefused,
	Hashtag:  "#tcpRefused",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisQUICTimeout,
	Hashtag:  "#quicTimeout",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisTLSTimeout,
	Hashtag:  "#tlsTimeout",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisTLSEOF,
	Hashtag:  "#tlsEOF",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisTLSReset,
	Hashtag:  "#tlsReset",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisCertificate,
	Hashtag:  "#certificate",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisHTTPDiff,
	Hashtag:  "#httpDiff",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisHTTPTimeout,
	Hashtag:  "#httpTimeout",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisHTTPReset,
	Hashtag:  "#httpReset",
	Severity: logcat.CONFIRMED,
}, {
	Flag:     AnalysisHTTPEOF,
	Hashtag:  "#httpEOF",
	Severity: logcat.UNEXPECTED,
}, {
	Flag:     AnalysisInconclusive,
	Hashtag:  "#inconclusive",
	Severity: logcat.SHRUG,
}, {
	Flag:     AnalysisProbeBug,
	Hashtag:  "#probeBug",
	Severity: logcat.BUG,
}, {
	Flag:     AnalysisHTTPDiffStatusCode,
	Hashtag:  "#httpDiffStatusCode",
	Severity: 0,
}, {
	Flag:     AnalysisHTTPDiffTitle,
	Hashtag:  "#httpDiffTitle",
	Severity: 0,
}, {
	Flag:     AnalysisHTTPDiffHeaders,
	Hashtag:  "#httpDiffHeaders",
	Severity: 0,
}, {
	Flag:     AnalysisHTTPDiffBodyLength,
	Hashtag:  "#httpDiffBodyLength",
	Severity: 0,
}, {
	Flag:     AnalysisHTTPDiffLegitimateRedirect,
	Hashtag:  "#httpDiffLegitimateRedirect",
	Severity: 0,
}, {
	Flag:     AnalysisHTTPDiffTransparentProxy,
	Hashtag:  "#httpDiffTransparentProxy",
	Severity: 0,
}}

// ExplainFlagsUsingTagsAndSeverity provides an explanation of a given set of flags
// in terms of a list of hashtags and a severity level.
func ExplainFlagsUsingTagsAndSeverity(flags int64) (tags []string, severity int64) {
	for _, e := range analysisDescriptions {
		if (flags & e.Flag) != 0 {
			tags = append(tags, e.Hashtag)
			severity |= e.Severity
		}
	}
	return
}

// Explainable is something for which we can explain a set of flags.
type Explainable interface {
	// Describe returns a description of the explainable.
	Describe() string
}

// ExplainFlagsWithLogging logs an explanation of the given flags.
func ExplainFlagsWithLogging(ei Explainable, flags int64) {
	tags, severity := ExplainFlagsUsingTagsAndSeverity(flags)
	logcat.Emitf(logcat.NOTICE, severity, "%s: %s", ei.Describe(), strings.Join(tags, " "))
}
