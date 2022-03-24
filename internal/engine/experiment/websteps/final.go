package websteps

//
// Final
//
// Contains code for final reprocessing.
//

import (
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
)

// finalLogging logs the overall results.
func (tk *TestKeys) finalLogging() {
	if tk.Flags != 0 {
		logcat.Stepf("summary of anomalous findings for %s:", tk.URL)
		for _, step := range tk.Steps {
			if step.Analysis == nil {
				continue // already logged in finalReprocessing
			}
			for _, dns := range step.Analysis.DNS {
				ExplainFlagsWithLogging(dns, dns.Flags)
			}
			for _, epnt := range step.Analysis.Endpoint {
				ExplainFlagsWithLogging(epnt, epnt.Flags)
			}
		}
	}
}

// finalReprocessingAndLogging performs the final reprocessing.
func (tk *TestKeys) finalReprocessing() {
	for idx, step := range tk.Steps {
		if step.Analysis == nil {
			logcat.Bugf("missing analysis for step %d of URL %s", idx, tk.URL)
			continue
		}
		for _, epnt := range step.Analysis.Endpoint {
			tk.finalReprocessingHTTPStatusDiff(epnt)
		}
	}
}

// finalReprocessingHTTPStatusDiff reprocesses all the analysis
// entries where the status code is inconsistent. There are cases
// where an HTTP (i.e., cleartext) request that would redirect
// in the TH succeeds immediately in the probe. It is not clear
// whether this happens because of HTTP caches in the network
// of the probe or the HTTP server serves the correct response
// immediately to the probe. Regardless of the root cause, it's
// important to undo the StatusDiff flag, which will result in
// an "anomaly" _when_ the probe receives the correct content in
// its HTTP request. In such a case, it seems more proper to
// emit a weaker (reserved) flag indicating what has happened.
func (tk *TestKeys) finalReprocessingHTTPStatusDiff(epnt *AnalysisEndpoint) {
	if (epnt.Flags & AnalysisHTTPDiffStatusCode) == 0 {
		return // skip the results we're not interested to
	}
	if epnt.probe == nil || epnt.th == nil {
		logcat.Bugf("[final] all HTTPDiff entries should have reprocessing info")
		return
	}
	if !epnt.th.IsHTTPRedirect() {
		return // we expect the TH to have seen a redirection
	}
	ph := epnt.probe.ResponseBodyTLSH()
	if tk.Bodies == nil || len(tk.Bodies.Bodies) < 1 {
		logcat.Bugf("[final] tk.Bodies is not properly initialized")
		return
	}
	entry, found := tk.Bodies.Bodies[ph]
	if !found {
		logcat.Bugf("[final] did not find my own body in tk.Bodies")
		return
	}
	// see if the same body was observed by another HTTP response
	another := false
	for _, ref := range entry.Refs {
		if epnt.probe.ID != ref {
			another = true
			break
		}
	}
	if !another {
		return // only observed by _this_ response
	}
	logcat.Infof("😅 [final] request #%d in #%d %s #%d %s %s",
		epnt.probe.ID, epnt.probe.URLMeasurementID,
		"has not been redirected like", epnt.th.ID,
		"but directly got a body we later observed (HTTP proxy?)",
		"so we need to take back our previous #httpDiffStatusCode diagnosis")
	epnt.Flags &= ^AnalysisHTTPDiffStatusCode
	epnt.Flags |= AnalysisHTTPMaybeProxy
}
