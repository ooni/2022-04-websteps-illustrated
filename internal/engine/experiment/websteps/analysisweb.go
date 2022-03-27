package websteps

//
// Analysis web
//
// Code for analyzing #httpDiff.
//

import (
	"reflect"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// analysisWebResult is the type of result returned by analysisWeb functions
type analysisWebResult int64

const (
	// analysisWebDiff indicates there's a diff
	analysisWebDiff = analysisWebResult(iota)

	// analysisWebMatch indicates there's no diff
	analysisWebMatch

	// analysisWebBug indicates there's a bug
	analysisWebBug

	// analysisWebInconclusive indicates we don't know
	analysisWebInconclusive
)

// analysisWebHTTPDiff returns whether we think that two EndpointMeasurement
// have HTTP differences. The return value contains scoring flags.
func analysisWebHTTPDiff(
	scoreID int64, epnt, otherEpnt *measurex.EndpointMeasurement) (flags int64) {

	// 1. perform all comparisons
	statusCode := analysisWebStatusCodeDiff(scoreID, epnt, otherEpnt)
	bodyLen := analysisWebBodyLengthDiff(scoreID, epnt, otherEpnt)
	uncommonHeaders := analysisWebHeadersDiff(scoreID, epnt, otherEpnt)
	title := analysisWebTitleDiff(scoreID, epnt, otherEpnt)

	// 2. check status code
	switch statusCode {
	case analysisWebDiff:
		flags |= AnalysisHTTPDiffStatusCode
	case analysisWebMatch:
		// nothing
	default:
		flags |= AnalysisProbeBug
	}

	// 2. check body length
	switch bodyLen {
	case analysisWebDiff:
		flags |= AnalysisHTTPDiffBodyLength
	case analysisWebMatch:
		// nothing
	default:
		flags |= AnalysisProbeBug
	}

	// 3. compare uncommon HTTP headers
	switch uncommonHeaders {
	case analysisWebDiff:
		flags |= AnalysisHTTPDiffHeaders
	case analysisWebMatch:
		// nothing
	default:
		flags |= AnalysisProbeBug
	}

	// 3. compare title
	switch title {
	case analysisWebDiff:
		flags |= AnalysisHTTPDiffTitle
	case analysisWebMatch:
		// nothing
	default:
		flags |= AnalysisProbeBug
	}

	if (flags & AnalysisProbeBug) != 0 {
		logcat.Bugf("[#%d] probe bug during analysis for #%d and #%d",
			scoreID, epnt.ID, otherEpnt.ID)
		return flags
	}

	if (flags & AnalysisHTTPDiffStatusCode) != 0 {
		logcat.Unexpectedf("[#%d] status code does not match for #%d and #%d: #httpDiff",
			scoreID, epnt.ID, otherEpnt.ID)
		return flags | AnalysisHTTPDiff
	}

	if (flags & AnalysisHTTPDiffBodyLength) == 0 {
		logcat.Celebratef(
			"[#%d] status code and body length match for #%d and #%d: accessible",
			scoreID, epnt.ID, otherEpnt.ID)
		return flags
	}

	if (flags & AnalysisHTTPDiffHeaders) == 0 {
		logcat.Celebratef(
			"[#%d] status code and uncommon headers match for #%d and #%d: accessible",
			scoreID, epnt.ID, otherEpnt.ID)
		return flags
	}

	if (flags & AnalysisHTTPDiffTitle) == 0 {
		logcat.Celebratef(
			"[#%d] status code and title match for #%d and #%d: accessible",
			scoreID, epnt.ID, otherEpnt.ID)
		return flags
	}

	logcat.Unexpectedf("[#%d] we conclude there's an #httpDiff for #%d and #%d",
		scoreID, epnt.ID, otherEpnt.ID)
	return flags | AnalysisHTTPDiff
}

// analysisWebStatusCodeDiff compares the status codes. This is where we deal
// with redirections specially to handle transparent proxies gracefully.
func analysisWebStatusCodeDiff(
	scoreID int64, epnt, otherEpnt *measurex.EndpointMeasurement) analysisWebResult {

	// 1. if the status code is exactly the same that's a match...
	match := epnt.StatusCode() == otherEpnt.StatusCode()
	if match {
		logcat.Infof(
			"[#%d] status code matches for #%d and #%d", scoreID, epnt.ID, otherEpnt.ID)
		return analysisWebMatch
	}

	// 2. handle the control being different from 3xx and 200
	//
	// Historically, Web Connectivity in MK and Pyton filtered out
	// 500 status codes to reduce false positives. Now, we're being
	// even more aggressive: we expect the TH to be able to access
	// a webpage (200 Ok) or be redirected. Any other outcome is
	// going to be inconclusive. Here are some potential cases in
	// which filtering more broadly could help:
	//
	// 1. say the server fails with 5xx (already covered in MK);
	//
	// 2. say the server is somehow protecting itself from scraping
	// from outside a country or cloud, and returns 204 (I've seen
	// 204 for http://iwannawatch.net, for example);
	//
	// 3. say there is an HTTP proxy in the TH environment and
	// we don't know it and the proxy says 403 Forbidden.
	//
	// We're going to mark all these cases as "inconclusive" and
	// assume the pipeline will be able to do a better job.
	if !otherEpnt.IsHTTPRedirect() && otherEpnt.StatusCode() != 200 {
		logcat.Shrugf(
			"[#%d] control response in #%d is neither 3xx nor 200: give up",
			scoreID, otherEpnt.ID)
		return analysisWebInconclusive
	}

	// 4. otherwise we have enough information to say there's #httpDiffStatusCode
	logcat.Infof(
		"[#%d] status code for #%d (%d) does not match #%d (%d)",
		scoreID, epnt.ID, epnt.StatusCode(), otherEpnt.ID, otherEpnt.StatusCode())
	return analysisWebDiff
}

// analysisWebBodyLengthDiff compares the body lengths.
func analysisWebBodyLengthDiff(
	scoreID int64, epnt, otherEpnt *measurex.EndpointMeasurement) analysisWebResult {

	// 1. truncated bodies
	//
	// We expect truncated bodies to have the same size because we are
	// sharing settings with the TH. If that's not the case, we've just
	// found a bug in the way in which we share settings.
	if epnt.BodyIsTruncated() && otherEpnt.BodyIsTruncated() {
		if epnt.BodyLength() == otherEpnt.BodyLength() {
			logcat.Noticef("[#%d] body length matches for #%d and #%d",
				scoreID, epnt.ID, otherEpnt.ID)
			return analysisWebMatch
		}
		logcat.Bugf("[#%d] body length does not match for #%d and #%d but %s",
			scoreID, epnt.ID, otherEpnt.ID, "both bodies are truncated")
		return analysisWebBug
	}
	if epnt.BodyIsTruncated() || otherEpnt.BodyIsTruncated() {
		logcat.Bugf("[#%d] just one of the two bodies is truncated", scoreID)
		return analysisWebBug
	}

	// 2. otherwise apply the original MK v0.10.11 algorithm
	var proportion float64
	const bodyProportionFactor = 0.7
	if epnt.BodyLength() >= otherEpnt.BodyLength() {
		proportion = float64(otherEpnt.BodyLength()) / float64(epnt.BodyLength())
	} else {
		proportion = float64(epnt.BodyLength()) / float64(otherEpnt.BodyLength())
	}
	mismatch := proportion <= bodyProportionFactor
	if mismatch {
		logcat.Infof(
			"[#%d] body length does not match for #%d (%d bytes) and #%d (%d bytes)",
			scoreID, epnt.ID, epnt.BodyLength(), otherEpnt.ID, otherEpnt.BodyLength())
		return analysisWebDiff
	}
	logcat.Infof(
		"[#%d] body length matches for #%d (%d bytes) and #%d (%d bytes)",
		scoreID, epnt.ID, epnt.BodyLength(), otherEpnt.ID, otherEpnt.BodyLength())
	return analysisWebMatch
}

//analysisWebTitleDiff compares the titles.
func analysisWebTitleDiff(
	scoreID int64, epnt, otherEpnt *measurex.EndpointMeasurement) analysisWebResult {
	control := otherEpnt.HTTPTitle
	measurement := epnt.HTTPTitle
	words := make(map[string]int)
	// We don't consider to match words that are shorter than 5
	// characters (5 is the average word length for english)
	//
	// The original implementation considered the word order but
	// considering different languages it seems we could have less
	// false positives by ignoring the word order.
	const minWordLength = 5
	for _, word := range strings.Split(measurement, " ") {
		if len(word) >= minWordLength {
			words[strings.ToLower(word)] |= analysisInMeasurement
		}
	}
	for _, word := range strings.Split(control, " ") {
		if len(word) >= minWordLength {
			words[strings.ToLower(word)] |= analysisInControl
		}
	}
	for _, score := range words {
		if (score & analysisInBoth) != analysisInBoth {
			logcat.Infof(
				"[#%d] title does not matches for #%d (%s) and #%d (%s)",
				scoreID, epnt.ID, epnt.HTTPTitle, otherEpnt.ID, otherEpnt.HTTPTitle)
			return analysisWebDiff
		}
	}
	logcat.Infof(
		"[#%d] title matches for #%d (%s) and #%d (%s)",
		scoreID, epnt.ID, epnt.HTTPTitle, otherEpnt.ID, otherEpnt.HTTPTitle)
	return analysisWebMatch
}

// analysisWebHeadersDiff compares uncommon headers.
func analysisWebHeadersDiff(
	scoreID int64, epnt, otherEpnt *measurex.EndpointMeasurement) analysisWebResult {

	// Implementation note: using map because we only care about the
	// keys being different and we ignore the values.
	measurement := epnt.ResponseHeaders()
	control := otherEpnt.ResponseHeaders()
	commonHeaders := map[string]bool{
		"date":                      true,
		"content-type":              true,
		"server":                    true,
		"cache-control":             true,
		"vary":                      true,
		"set-cookie":                true,
		"location":                  true,
		"expires":                   true,
		"x-powered-by":              true,
		"content-encoding":          true,
		"last-modified":             true,
		"accept-ranges":             true,
		"pragma":                    true,
		"x-frame-options":           true,
		"etag":                      true,
		"x-content-type-options":    true,
		"age":                       true,
		"via":                       true,
		"p3p":                       true,
		"x-xss-protection":          true,
		"content-language":          true,
		"cf-ray":                    true,
		"strict-transport-security": true,
		"link":                      true,
		"x-varnish":                 true,
	}
	matching := make(map[string]int)
	ours := make(map[string]bool)
	for key := range measurement {
		key = strings.ToLower(key)
		if _, ok := commonHeaders[key]; !ok {
			matching[key] |= analysisInMeasurement
		}
		ours[key] = true
	}
	theirs := make(map[string]bool)
	for key := range control {
		key = strings.ToLower(key)
		if _, ok := commonHeaders[key]; !ok {
			matching[key] |= analysisInControl
		}
		theirs[key] = true
	}
	// if they are equal we're done
	if good := reflect.DeepEqual(ours, theirs); good {
		logcat.Infof("[#%d] uncommon headers are equal for #%d and #%d",
			scoreID, epnt.ID, otherEpnt.ID)
		return analysisWebMatch
	}
	// compute the intersection of uncommon headers
	for _, value := range matching {
		if (value & analysisInBoth) == analysisInBoth {
			logcat.Infof(
				"[#%d] uncommon headers intersection for #%d and #%d is not empty",
				scoreID, epnt.ID, otherEpnt.ID)
			return analysisWebMatch
		}
	}
	logcat.Infof(
		"[#%d] uncommon headers intersection for #%d and #%d is empty",
		scoreID, epnt.ID, otherEpnt.ID)
	return analysisWebDiff
}
