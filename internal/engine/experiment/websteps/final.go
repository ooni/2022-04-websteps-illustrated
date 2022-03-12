package websteps

//
// Final
//
// Contains code for final reprocessing.
//

import "github.com/bassosimone/websteps-illustrated/internal/model"

// finalReprocessingAndLogging performs the final reprocessing. Once each
// piece of analysis is final, the code will log it.
func (tk *TestKeys) finalReprocessingAndLogging(logger model.Logger) {
	for _, step := range tk.Steps {
		if step.Analysis == nil {
			continue // no analysis? nothing to do
		}
		for _, dns := range step.Analysis.DNS {
			ExplainFlagsWithLogging(logger, dns, dns.Flags)
		}
		for _, epnt := range step.Analysis.Endpoint {
			tk.finalReprocessingHTTPStatusDiff(logger, epnt)
			ExplainFlagsWithLogging(logger, epnt, epnt.Flags)
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
func (tk *TestKeys) finalReprocessingHTTPStatusDiff(
	logger model.Logger, epnt *AnalysisEndpoint) {
	if (epnt.Flags & AnalysisHTTPDiffStatusCode) == 0 {
		return // skip the results we're not interested to
	}
	if epnt.probe == nil || epnt.th == nil {
		logger.Warnf("[final] BUG: all HTTPDiff entries should have reprocessing info")
		return
	}
	if !epnt.th.IsHTTPRedirect() {
		return // we expect the TH to have seen a redirection
	}
	ph := epnt.probe.ResponseBodyTLSH()
	if tk.Bodies == nil || len(tk.Bodies.Bodies) < 1 {
		logger.Warnf("[final] BUG: tk.Bodies is not properly initialized")
		return
	}
	entry, found := tk.Bodies.Bodies[ph]
	if !found {
		logger.Warnf("[final] BUG: did not find my own body in tk.Bodies")
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
	logger.Infof("😅 [final] request #%d in #%d %s #%d %s %s",
		epnt.probe.ID, epnt.probe.URLMeasurementID,
		"has not been redirected like", epnt.th.ID,
		"but directly got a body we later observed (HTTP proxy?)",
		"so we need to take back our previous #httpDiffStatusCode diagnosis")
	epnt.Flags &= ^AnalysisHTTPDiffStatusCode
	epnt.Flags |= AnalysisHTTPMaybeProxy
}
