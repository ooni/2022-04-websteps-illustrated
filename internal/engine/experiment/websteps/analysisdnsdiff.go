package websteps

//
// Analysis DNS diff
//
// Code for analyzing cases of DNS diff
//

import (
	"strings"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"golang.org/x/net/publicsuffix"
)

// analysisDNSDiffCheck checks whether it's reasonable to say that lookup compared
// to peerLookup contains a different set of IP addresses (aka #dnsDiff).
func analysisDNSDiffCheck(scoreID int64, lookup,
	peerLookup *measurex.DNSLookupMeasurement,
	otherLookups []*measurex.DNSLookupMeasurement,
	epnts ...[]*measurex.EndpointMeasurement) int64 {

	// 1. check whether there is overlap in the returned IP addrs. In such a case
	// it's quite difficult to argue that lookup isn't legit.
	if analysisDNSDiffHasOverlappingAddrs(scoreID, lookup, peerLookup) {
		return 0
	}

	// 2. check whether we can find common "public suffix" for any of
	// the IP addresses returned by the probe and the TH.
	//
	// This check was not in MK. A simpler version of this check
	// was implemented by the original ooniprobe.
	//
	// Note that this check is here to privilege false negatives over
	// false positives. It may be possible for a censor to configure
	// a reverse lookup exactly like the correct reverse lookup for the
	// legit host. Also, it could happen that the legit page and the
	// block page are hosted by the same cloud provider and hence both
	// belong to the same public suffix.
	if analysisDNSHasOverlappingReverseLookups(scoreID, lookup, peerLookup, otherLookups) {
		return 0
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
	// See the above comment regarding false positives and false negatives.
	if analysisDNSHasOverlappingANSs(scoreID, lookup, peerLookup) {
		return 0
	}

	// 4. conclude that measurement and control are inconsistent
	logcat.Unexpectedf("[#%d] we conclude that #%d and #%d are #dnsDiff",
		scoreID, lookup.ID, peerLookup.ID)
	return AnalysisDNSDiff
}

// analysisDNSDiffHasOverlappingAddrs returns whether there's overlap between the IP
// addresses returned by lookup and the ones returned by peerLookup.
func analysisDNSDiffHasOverlappingAddrs(
	scoreID int64, lookup, peerLookup *measurex.DNSLookupMeasurement) bool {
	logcat.Infof(
		"[#%d] checking whether #%d and #%d have overlapping IP addresses",
		scoreID, lookup.ID, peerLookup.ID)
	ipmap := make(map[string]int)
	for _, addr := range lookup.Addresses() {
		ipmap[addr] |= analysisInMeasurement
	}
	for _, addr := range peerLookup.Addresses() {
		ipmap[addr] |= analysisInControl
	}
	for key, value := range ipmap {
		// just in case an empty string slipped through
		if key != "" && (value&analysisInBoth) == analysisInBoth {
			logcat.Celebratef("[#%d] #%d and #%d have overlapping IP address %s",
				scoreID, lookup.ID, peerLookup.ID, key)
			return true
		}
	}
	return false
}

// analysisDNSDiffHasOverlappingReverseLookups returns whether there's overlap between
// the reverse lookup of the IP addresses returned by lookup and the reverse lookup
// of the ones returned by peerLookup. This comparison operates and the public suffixes
// derived from reverse lookup results rather than on the results themselves.
func analysisDNSHasOverlappingReverseLookups(
	scoreID int64, lookup, peerLookup *measurex.DNSLookupMeasurement,
	otherLookups []*measurex.DNSLookupMeasurement) bool {

	// 2.1. map every IP address to the known public suffixes for it
	logcat.Infof(
		"[#%d] checking whether #%d and #%d have overlapping reverse lookups",
		scoreID, lookup.ID, peerLookup.ID)
	suffixes := make(map[string][]string)
	for _, dns := range otherLookups {
		if dns.LookupType() != archival.DNSLookupTypeReverse {
			continue
		}
		for _, ptr := range dns.PTRs() {
			ptr = strings.TrimSuffix(ptr, ".")
			suffix, err := publicsuffix.EffectiveTLDPlusOne(ptr)
			if err != nil {
				logcat.Shrugf("cannot find pubblic suffix for %s: %s", ptr, err.Error())
				continue // probably a corner case
			}
			suffixes[dns.ReverseAddress] = append(suffixes[dns.ReverseAddress], suffix)
		}
	}

	// 2.2. compute the intersection between probe and TH results
	suffmap := make(map[string]int64)
	for _, addr := range lookup.Addresses() {
		for _, suf := range suffixes[addr] {
			suffmap[suf] |= analysisInMeasurement
		}
	}
	for _, addr := range peerLookup.Addresses() {
		for _, suf := range suffixes[addr] {
			suffmap[suf] |= analysisInControl
		}
	}

	// 2.3. declare there's no DNS diff if we find a common intersection
	for key, value := range suffmap {
		if (value & analysisInBoth) == analysisInBoth {
			logcat.Celebratef(
				"[#%d] #%d and #%d have overlapping reverse lookups for %s",
				scoreID, lookup.ID, peerLookup.ID, key)
			return true
		}
	}

	return false
}

// analysisDNSDiffHasOverlappingASNs returns whether there's overlap between
// the ASNs of the IP addresses returned by lookup and the ANSs of the ones
// returned by peerLookup. We use the bundled ASN database for that.
func analysisDNSHasOverlappingANSs(
	scoreID int64, lookup, peerLookup *measurex.DNSLookupMeasurement) bool {
	logcat.Infof("[#%d] checking whether #%d and #%d have overlapping ASNs",
		scoreID, lookup.ID, peerLookup.ID)
	asnmap := make(map[uint]int64)
	for _, addr := range lookup.Addresses() {
		if asnum := analysisMapAddrToASN(addr); asnum != 0 {
			asnmap[asnum] |= analysisInMeasurement
		}
	}
	for _, addr := range peerLookup.Addresses() {
		if asnum := analysisMapAddrToASN(addr); asnum != 0 {
			asnmap[asnum] |= analysisInControl
		}
	}
	for key, value := range asnmap {
		if (value & analysisInBoth) == analysisInBoth {
			logcat.Celebratef("[#%d] #%d and #%d have overlapping ASN: AS%d",
				scoreID, lookup.ID, peerLookup.ID, key)
			return true
		}
	}
	return false
}
