package websteps

import (
	"reflect"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/engine/geolocate"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"golang.org/x/net/publicsuffix"
)

//
// Web Connectivity
//
// This file contains Web Connectivity algorithms.
//

// dnsWebConnectivityDNSDiff is the DNSDiff algorithm originally
// designed for Web Connectivity and now adapted to websteps.
func (ssm *SingleStepMeasurement) dnsWebConnectivityDNSDiff(scoreID int64,
	pq, thq *measurex.DNSLookupMeasurement, thResp *THResponse) bool {

	// we use these flags to classify who did see what
	const (
		inMeasurement = 1 << 0
		inControl     = 1 << 1
		inBoth        = inMeasurement | inControl
	)

	// 1. check whether there is overlap in the returned IP addresses
	ipmap := make(map[string]int)
	for _, addr := range pq.Addresses() {
		ipmap[addr] |= inMeasurement
	}
	for _, addr := range thq.Addresses() {
		ipmap[addr] |= inControl
	}
	for key, value := range ipmap {
		// just in case an empty string slipped through
		if key != "" && (value&inBoth) == inBoth {
			return false // no diff
		}
	}
	logcat.Noticef("[#%d] #%d and #%d do not have overlapping IP addresses (maybe #dnsDiff?)", scoreID, pq.ID, thq.ID)

	// 2. check whether we can find common "public suffix" for any of
	// the IP addresses returned by the probe and the TH.
	//
	// This check was not in MK. A simpler version of this check
	// was implemented by the original ooniprobe.
	if thResp != nil {
		// 1.1. map every IP address to the known public suffixes for it
		suffixes := make(map[string][]string)
		for _, dns := range thResp.DNS {
			if dns.LookupType() != archival.DNSLookupTypeReverse {
				continue
			}
			for _, ptr := range dns.PTRs() {
				suffix, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(ptr, "."))
				if err != nil {
					continue // probably a corner case
				}
				suffixes[dns.ReverseAddress] = append(suffixes[dns.ReverseAddress], suffix)
			}
		}
		// 1.2. compute the intersection between probe and TH results
		suffmap := make(map[string]int64)
		for _, addr := range pq.Addresses() {
			for _, suf := range suffixes[addr] {
				suffmap[suf] |= inMeasurement
			}
		}
		for _, addr := range thq.Addresses() {
			for _, suf := range suffixes[addr] {
				suffmap[suf] |= inControl
			}
		}
		// 1.3. declare there's no DNS diff if we find a common intersection
		for _, value := range suffmap {
			if (value & inBoth) == inBoth {
				return false // no diff
			}
		}
		// 1.4. explain to the user why this lookup failed.
		if len(suffmap) > 0 {
			logcat.Noticef("[#%d] #%d and #%d do not have overlapping reverse DNS lookups (maybe #dnsDiff?)", scoreID, pq.ID, thq.ID)
		}
	}

	// 3. stop if measurement and control returned IP addresses
	// that belong to the same Autonomous System(s).
	//
	// This specific check is present in MK's implementation.
	//
	// Note that this covers also the cases where the measurement contains only
	// bogons while the control does not contain bogons (even though now in
	// websteps we check for bogons before invoking this algorithm).
	//
	// Note that this of course covers the cases where results are equal.
	asnmap := make(map[uint]int64)
	for _, addr := range pq.Addresses() {
		if asnum := ssm.dnsMapAddrToASN(addr); asnum != 0 {
			asnmap[asnum] |= inMeasurement
		}
	}
	for _, addr := range thq.Addresses() {
		if asnum := ssm.dnsMapAddrToASN(addr); asnum != 0 {
			asnmap[asnum] |= inControl
		}
	}
	for _, value := range asnmap {
		if (value & inBoth) == inBoth {
			return false // no diff
		}
	}
	if len(asnmap) > 0 {
		logcat.Noticef("[#%d] #%d and #%d do not have overlapping ASNs (maybe #dnsDiff?)", scoreID, pq.ID, thq.ID)
	}

	// 4. check whether addresses returned by the TH work with HTTPS. This check is a
	// very conservative one that privileges false negative over false positives.
	if !ssm.dnsAnyIPAddrWorksWithHTTPS(scoreID, thq) {
		logcat.Noticef("[#%d] no IP addresses in #%d work with HTTPS", scoreID, thq.ID)
		logcat.Noticef("[#%d] this may be #dnsDiff but I'll leave this case to the pipeline to analyze", scoreID)
		return false
	}
	if !ssm.dnsNoIPAddrWorksWithHTTPS(scoreID, pq) {
		logcat.Bugf("[#%d] I thought I previously determined no addr in #%d worked with HTTPS", scoreID, pq.ID)
		logcat.Bugf("[#%d] because this does not seem to be the case now, I think there's a bug", scoreID)
		logcat.Noticef("[#%d] this may be #dnsDiff but I'll leave this case to the pipeline to analyze", scoreID)
		return false
	}

	// 5. conclude that measurement and control are inconsistent
	logcat.Noticef("[#%d] considering all the above, I am going to conclude #%d and #%d are #dnsDiff", scoreID, pq.ID, thq.ID)
	return true
}

// dnsMapAddrToASN maps an IP address to an ASN number. In cae
// of failure, this function returns zero.
func (ssm *SingleStepMeasurement) dnsMapAddrToASN(addr string) uint {
	asn, _, _ := geolocate.LookupASN(addr)
	return asn
}

// endpointWebConnectivityBodyLengthChecks is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (ssm *SingleStepMeasurement) endpointWebConnectivityBodyLengthChecks(
	pe, the *measurex.EndpointMeasurement) (flags int64) {
	// We expect truncated bodies to have the same size because we are
	// sharing settings with the TH. If that's not the case, we've just
	// found a bug in the way in which we share settings.
	if pe.BodyIsTruncated() && the.BodyIsTruncated() == pe.BodyIsTruncated() {
		if pe.BodyLength() != the.BodyLength() {
			flags |= AnalysisProbeBug
		}
		return
	}
	var proportion float64
	const bodyProportionFactor = 0.7
	if pe.BodyLength() >= the.BodyLength() {
		proportion = float64(the.BodyLength()) / float64(pe.BodyLength())
	} else {
		proportion = float64(pe.BodyLength()) / float64(the.BodyLength())
	}
	mismatch := proportion <= bodyProportionFactor
	if mismatch {
		flags |= AnalysisHTTPDiffBodyLength
	}
	return
}

// endpointWebConnectivityStatusCodeMatch is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (ssm *SingleStepMeasurement) endpointWebConnectivityStatusCodeMatch(
	pe, the *measurex.EndpointMeasurement) (flags int64) {
	match := pe.StatusCode() == the.StatusCode()
	if match {
		// if the status codes are equal, they clearly match
		return
	}
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
	// We're going to mark all these cases as "gave up analysis".
	if !the.IsHTTPRedirect() && the.StatusCode() != 200 {
		flags |= AnalysisGiveUp
		logcat.Shrug("[analysis] TH response is neither 3xx nor 200: give up")
		return
	}
	flags |= AnalysisHTTPDiffStatusCode
	return
}

// endpointWebConnectivityHeadersMatch is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (ssm *SingleStepMeasurement) endpointWebConnectivityHeadersMatch(
	pe, the *measurex.EndpointMeasurement) (flags int64) {
	// Implementation note: using map because we only care about the
	// keys being different and we ignore the values.
	control := the.ResponseHeaders()
	measurement := pe.ResponseHeaders()
	const (
		inMeasurement = 1 << 0
		inControl     = 1 << 1
		inBoth        = inMeasurement | inControl
	)
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
			matching[key] |= inMeasurement
		}
		ours[key] = true
	}
	theirs := make(map[string]bool)
	for key := range control {
		key = strings.ToLower(key)
		if _, ok := commonHeaders[key]; !ok {
			matching[key] |= inControl
		}
		theirs[key] = true
	}
	// if they are equal we're done
	if good := reflect.DeepEqual(ours, theirs); good {
		return
	}
	// compute the intersection of uncommon headers
	var intersection int
	for _, value := range matching {
		if (value & inBoth) == inBoth {
			intersection++
		}
	}
	if intersection > 0 {
		return
	}
	flags |= AnalysisHTTPDiffHeaders
	return
}

// endpointWebConnectivityTitleMatch is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (ssm *SingleStepMeasurement) endpointWebConnectivityTitleMatch(
	pe, the *measurex.EndpointMeasurement) (flags int64) {
	control := the.HTTPTitle
	measurement := pe.HTTPTitle
	const (
		inMeasurement = 1 << 0
		inControl     = 1 << 1
		inBoth        = inMeasurement | inControl
	)
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
			words[strings.ToLower(word)] |= inMeasurement
		}
	}
	for _, word := range strings.Split(control, " ") {
		if len(word) >= minWordLength {
			words[strings.ToLower(word)] |= inControl
		}
	}
	for _, score := range words {
		if (score & inBoth) != inBoth {
			flags |= AnalysisHTTPDiffTitle
			return
		}
	}
	return
}
