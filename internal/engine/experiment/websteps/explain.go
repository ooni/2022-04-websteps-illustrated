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

const (
	// AnalysisSeverityConfirmed is used when see anomalies that
	// are most likely symptoms of censorship.
	AnalysisSeverityConfirmed = 1 << iota

	// AnalysisSeverityUnexpected is used when we see anomalies that
	// may be symptoms of censorship but are less conclusive.
	AnalysisSeverityUnexpected
)

// analysisDescriptions contains all the analysis flags descriptions.
var analysisDescriptions = []*AnalysisDescription{{
	Flag:     AnalysisDNSNXDOMAIN,
	Hashtag:  "#nxdomain",
	Severity: AnalysisSeverityConfirmed,
}, {
	Flag:     AnalysisDNSTimeout,
	Hashtag:  "#dnsTimeout",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisDNSBogon,
	Hashtag:  "#bogon",
	Severity: AnalysisSeverityConfirmed,
}, {
	Flag:     AnalysisDNSDiff,
	Hashtag:  "#dnsDiff",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisEpntTCPTimeout,
	Hashtag:  "#tcpTimeout",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisEpntTCPRefused,
	Hashtag:  "#tcpRefused",
	Severity: AnalysisSeverityConfirmed,
}, {
	Flag:     AnalysisEpntQUICTimeout,
	Hashtag:  "#quicTimeout",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisEpntTLSTimeout,
	Hashtag:  "#tlsTimeout",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisEpntTLSEOF,
	Hashtag:  "#tlsEOF",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisEpntTLSReset,
	Hashtag:  "#tlsReset",
	Severity: AnalysisSeverityConfirmed,
}, {
	Flag:     AnalysisEpntCertificate,
	Hashtag:  "#certificate",
	Severity: AnalysisSeverityConfirmed,
}, {
	Flag:     AnalysisHTTPTimeout,
	Hashtag:  "#httpTimeout",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisHTTPReset,
	Hashtag:  "#httpReset",
	Severity: AnalysisSeverityConfirmed,
}, {
	Flag:     AnalysisHTTPEOF,
	Hashtag:  "#httpEOF",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisHTTPDiffStatusCode,
	Hashtag:  "#httpDiffStatusCode",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisHTTPDiffHeaders,
	Hashtag:  "#httpDiffHeaders",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisHTTPDiffTitle,
	Hashtag:  "#httpDiffTitle",
	Severity: AnalysisSeverityUnexpected,
}, {
	Flag:     AnalysisHTTPDiffBodyLength,
	Hashtag:  "#httpDiffBodyLength",
	Severity: AnalysisSeverityUnexpected,
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
func ExplainFlagsWithLogging(logger model.Logger, ei Explainable, flags int64) {
	tags, severity := ExplainFlagsUsingTagsAndSeverity(flags)
	var emoji string
	switch {
	case (severity & AnalysisSeverityConfirmed) != 0:
		emoji = "🔥"
	case (severity & AnalysisSeverityUnexpected) != 0:
		emoji = "❓"
	default:
		return // just show what needs the most attention
	}
	logger.Infof("<%s> %s: %s", emoji, ei.Describe(), strings.Join(tags, " "))
}
