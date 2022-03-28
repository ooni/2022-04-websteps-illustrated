package websteps

//
// Analysis TH
//
// Contains code to cross compare TH results.
//

import (
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// analyzeTHResults attempts to cross compare TH results between each other to figure
// out whether the probe's DNS results are compatible with the TH's ones. This function
// returns a nil slice if there are no TH measurements to analyze.
func (ssm *SingleStepMeasurement) analyzeTHResults(
	amx measurex.AbstractMeasurer) (out []*AnalysisEndpoint) {
	if ssm.ProbeInitial == nil || ssm.TH == nil {
		logcat.Emitf(logcat.DEBUG, logcat.SHRUG, "passed nil ProbeInitial or TH")
		return
	}
	logcat.Substep(
		"cross-comparing TH endpoint results grouped by who resolved the related IP addresses")

	// 1. obtain IP addresses resolved by the probe.
	probeAddrs, found := analysisTHObtainProbeAddresses(ssm.ProbeInitial.DNS)
	if !found {
		logcat.Shrugf("analyzeTHResults: can't obtain probe's IP addresses")
		return
	}
	logcat.Infof("IP addresses resolved by the probe: %+v", probeAddrs)

	// 2. split TH measurements in "probe" and "th" derived sets.
	probeSet, thSet, canContinue := analysisTHPartitionResults(probeAddrs, ssm.TH.Endpoint)
	if !canContinue {
		return
	}

	// 3. perform cross comparison proper
	for _, epnt := range probeSet {
		logcat.Infof("considering %s in the IP-resolved-by-probe set", epnt.Describe())
		if epnt.Failure != "" {
			logcat.Infof("skipping %s because it failed", epnt.Describe())
			continue
		}
		if epnt.Scheme() != "http" {
			logcat.Infof("skipping %s because it's not http", epnt.Describe())
			continue
		}
		for _, otherEpnt := range thSet {
			logcat.Infof("considering %s in the IP-resolved-by-TH set", otherEpnt.Describe())
			if otherEpnt.Failure != "" {
				logcat.Infof("skipping %s because it failed", otherEpnt.Describe())
				continue
			}
			if otherEpnt.Scheme() != "http" {
				logcat.Infof("skipping %s because it's not http", otherEpnt.Describe())
				continue
			}
			score := &AnalysisEndpoint{
				ID:               amx.NextID(),
				URLMeasurementID: ssm.ProbeInitialURLMeasurementID(),
				Refs:             []int64{epnt.ID, otherEpnt.ID},
				Flags:            0,
			}
			logcat.Inspectf("[#%d] comparing #%d to #%d", score.ID, epnt.ID, otherEpnt.ID)
			score.Flags |= analysisWebHTTPDiff(score.ID, epnt, otherEpnt)
			out = append(out, score)
		}
	}

	// 4. remove unflagged results and return
	return endpointAnalysisRemoveUnflaggedResults(out)
}

// analysisTHObtainProbeAddresses returns all the addresses resolved by the probe.
func analysisTHObtainProbeAddresses(
	dns []*measurex.DNSLookupMeasurement) (map[string]int, bool) {
	uniq := map[string]int{}
	for _, dentry := range dns {
		for _, addr := range dentry.Addresses() {
			uniq[addr]++
		}
	}
	return uniq, len(uniq) > 0
}

// analysisTHPartitionResults splits the TH results in two partitions: the
// results caused by probe lookups and the results caused by TH lookups. Note
// that this function returns an empty TH lookups (and false) in case both
// the probe and the TH resolved the same addresses.
func analysisTHPartitionResults(
	probeAddrs map[string]int, epnt []*measurex.EndpointMeasurement) (
	probeSet, thSet []*measurex.EndpointMeasurement, canContinueCheck bool) {
	for _, e := range epnt {
		ipAddr := e.IPAddress()
		if ipAddr == "" {
			continue
		}
		if _, found := probeAddrs[ipAddr]; found {
			logcat.Infof("inside IP-resolved-by-probe set: %s", e.Describe())
			probeSet = append(probeSet, e)
		} else {
			logcat.Infof("inside IP-resolved-by-TH set: %s", e.Describe())
			thSet = append(thSet, e)
		}
	}
	return probeSet, thSet, len(probeSet) > 0 && len(thSet) > 0
}
