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
	probeAddrs, found := analysisTHObtainAddresses(ssm.ProbeInitial.DNS)
	if !found {
		logcat.Shrugf("analyzeTHResults: can't obtain probe's IP addresses")
		return
	}
	logcat.Infof("IP addresses resolved by the probe: %+v", probeAddrs)

	// 2. obtain IP addresses resolved by the TH.
	thAddrs, found := analysisTHObtainAddresses(ssm.TH.DNS)
	if !found {
		logcat.Shrugf("analyzeTHResults: can't obtain TH's IP addresses")
		return
	}
	logcat.Infof("IP addresses resolved by the TH: %+v", thAddrs)

	// 3. discover IP addresses resolved only by the probe.
	onlyProbe := analysisTHAddressSetDiff(probeAddrs, thAddrs)
	logcat.Infof("IP addresses resolved only by the probe: %+v", onlyProbe)

	if len(onlyProbe) < 1 {
		logcat.Info("no IP address only seen by the probe, so nothing to do here")
		return
	}

	// 4. split TH measurements in "probe" and "th" derived sets.
	probeSet, thSet, canContinue := analysisTHPartitionResults(onlyProbe, ssm.TH.Endpoint)
	if !canContinue {
		return
	}

	// 5. perform cross comparison proper
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

	// 6. remove unflagged results and return
	return endpointAnalysisRemoveUnflaggedResults(out)
}

// analysisTHAddressSetDiff returns the addrs that only appear in the A set.
func analysisTHAddressSetDiff(A, B []string) (o []string) {
	uniq := map[string]int64{}
	for _, a := range A {
		uniq[a] |= analysisInMeasurement
	}
	for _, b := range B {
		uniq[b] |= analysisInControl
	}
	for addr, flags := range uniq {
		if flags == analysisInMeasurement {
			o = append(o, addr)
		}
	}
	return
}

// analysisTHObtainAddresses returns all the addresses inside a given set of lookups.
func analysisTHObtainAddresses(dns []*measurex.DNSLookupMeasurement) ([]string, bool) {
	uniq := map[string]int{}
	for _, dentry := range dns {
		for _, addr := range dentry.Addresses() {
			uniq[addr]++
		}
	}
	out := []string{}
	for addr := range uniq {
		out = append(out, addr)
	}
	return out, len(out) > 0
}

// analysisTHPartitionResults splits the TH results in two partitions: the
// results caused by probe lookups and the results caused by TH lookups. Note
// that this function returns an empty TH lookups (and false) in case both
// the probe and the TH resolved the same addresses.
func analysisTHPartitionResults(
	onlyProbe []string, epnt []*measurex.EndpointMeasurement) (
	probeSet, thSet []*measurex.EndpointMeasurement, canContinueCheck bool) {
	paddrs := map[string]bool{}
	for _, a := range onlyProbe {
		paddrs[a] = true
	}
	for _, e := range epnt {
		ipAddr := e.IPAddress()
		if ipAddr == "" {
			continue
		}
		if _, found := paddrs[ipAddr]; found {
			logcat.Infof("inside IP-resolved-by-probe set: %s", e.Describe())
			probeSet = append(probeSet, e)
		} else {
			logcat.Infof("inside IP-resolved-by-TH set: %s", e.Describe())
			thSet = append(thSet, e)
		}
	}
	return probeSet, thSet, len(probeSet) > 0 && len(thSet) > 0
}
