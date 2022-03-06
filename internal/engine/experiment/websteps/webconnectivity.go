package websteps

import (
	"reflect"
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/engine/geolocate"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

//
// Web Connectivity
//
// This file contains Web Connectivity algorithms.
//

// dnsWebConnectivityDNSDiff is the DNSDiff algorithm originally
// designed for Web Connectivity and now adapted to websteps.
func (tk *TestKeys) dnsWebConnectivityDNSDiff(
	pq, thq *measurex.DNSLookupMeasurement) (flags int64) {
	// 1. stop if measurement and control returned IP addresses
	// that belong to the same Autonomous System(s).
	//
	// This specific check is present in MK's implementation.
	//
	// Note that this covers also the cases where the measurement contains only
	// bogons while the control does not contain bogons (even though now in
	// websteps we check for bogons before invoking this algorithm).
	//
	// Note that this of course covers the cases where results are equal.
	const (
		inMeasurement = 1 << 0
		inControl     = 1 << 1
		inBoth        = inMeasurement | inControl
	)
	asnmap := make(map[uint]int64)
	for _, addr := range pq.Addresses() {
		asnmap[tk.dnsMapAddrToASN(addr)] |= inMeasurement
	}
	for _, addr := range thq.Addresses() {
		asnmap[tk.dnsMapAddrToASN(addr)] |= inControl
	}
	for key, value := range asnmap {
		// Note: zero means that the ASN lookup failed
		if key != 0 && (value&inBoth) == inBoth {
			return
		}
	}

	// 2. when ASN lookup failed (unlikely), check whether
	// there is overlap in the returned IP addresses
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
			return
		}
	}

	// 3. conclude that measurement and control are inconsistent
	flags |= AnalysisFlagDiffDNS | AnalysisFlagUnexpected
	return
}

// dnsMapAddrToASN maps an IP address to an ASN number. In cae
// of failure, this function returns zero.
func (tk *TestKeys) dnsMapAddrToASN(addr string) uint {
	asn, _, _ := geolocate.LookupASN(addr)
	return asn
}

// endpointWebConnectivityBodyLengthChecks is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (tk *TestKeys) endpointWebConnectivityBodyLengthChecks(
	pe, the *measurex.EndpointMeasurement) (flags int64) {
	// We expect truncated bodies to have the same size because we are
	// sharing settings with the TH. If that's not the case, we've just
	// found a bug in the way in which we share settings.
	if pe.BodyIsTruncated() && the.BodyIsTruncated() == pe.BodyIsTruncated() {
		if pe.BodyLength() != the.BodyLength() {
			flags |= AnalysisFlagProbeBug
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
		flags |= AnalysisFlagDiffHTTP | AnalysisFlagHTTPDiffBodyLength | AnalysisFlagUnexpected
	}
	return
}

// endpointWebConnectivityStatusCodeMatch is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (tk *TestKeys) endpointWebConnectivityStatusCodeMatch(
	pe, the *measurex.EndpointMeasurement) (flags int64) {
	match := pe.StatusCode() == the.StatusCode()
	if match {
		// if the status codes are equal, they clearly match
		return
	}
	// This fix is part of Web Connectivity in MK and in Python since
	// basically forever; my recollection is that we want to work around
	// cases where the test helper is failing(?!). Unlike previous
	// implementations, this implementation avoids a false positive
	// when both measurement and control statuses are 500.
	if the.StatusCode()/100 == 5 {
		flags |= AnalysisFlagProbeBug // tell us the TH is misbehaving?!
		return
	}
	flags |= AnalysisFlagDiffHTTP | AnalysisFlagHTTPDiffStatusCode | AnalysisFlagUnexpected
	return
}

// endpointWebConnectivityHeadersMatch is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (tk *TestKeys) endpointWebConnectivityHeadersMatch(
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
	flags |= AnalysisFlagDiffHTTP | AnalysisFlagHTTPDiffHeaders | AnalysisFlagUnexpected
	return
}

// endpointWebConnectivityTitleMatch is part of the HTTPDiff algorithm
// designed for Web Connectivity and now adapted to websteps.
func (tk *TestKeys) endpointWebConnectivityTitleMatch(
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
			flags |= AnalysisFlagDiffHTTP | AnalysisFlagHTTPDiffTitle | AnalysisFlagUnexpected
			return
		}
	}
	return
}
