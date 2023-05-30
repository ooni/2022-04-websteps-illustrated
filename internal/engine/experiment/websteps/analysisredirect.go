package websteps

//
// Analysis redirect
//
// Deals with false positives caused by unexpected redirects.
//

import (
	"net/http"

	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/measurex"
)

// analysisRedirectTransparentProxyCheck tries to detect a false positive
// caused by a transparent HTTP proxy that returns a legitimate result
// to the probe saving a redirec to HTTPS. Here's a real world situation
// where this happens for me in Vodafone Italy (AS30722):
//
// - the reference URL is http://ajax.aspnetcdn.com/ajax/4.5.2/1/MicrosoftAjax.js;
//
// - the TH sees a redirect to the same URL except it uses HTTPS;
//
// - the corresponding TH measurement is 200 OK;
//
// - the probe sees 200 OK immediately for the HTTP request.
//
// So, we try to match the case above and, if that is the case we return
// true to the caller, otherwise we return false.
func analysisRedirectTransparentProxyCheck(
	scoreID int64, epnt, otherEpnt *measurex.EndpointMeasurement,
	otherEpnts []*measurex.EndpointMeasurement) (int64, bool) {
	if epnt.StatusCode() != 200 {
		return 0, false // does not match the pattern
	}
	if !otherEpnt.IsHTTPRedirect() {
		return 0, false // does not match the pattern
	}
	location := otherEpnt.Location
	if location == nil {
		logcat.Bugf("[#%d] redirect without location: %s", scoreID, otherEpnt.Summary())
		return 0, false
	}
	url := epnt.URL
	if url == nil {
		logcat.Bugf("[#%d] endpoint measurement without URL: %s", scoreID, epnt.Summary())
		return 0, false
	}
	if url.Scheme != "http" || location.Scheme != "https" {
		return 0, false // does not match the pattern
	}
	if url.Hostname() != location.Hostname() {
		return 0, false // does not match the pattern
	}
	if url.Port() != "" && location.Port() != "" {
		return 0, false // we're not able to deal with custom ports for now
	}
	if url.Path != location.Path {
		return 0, false // does not match the pattern
	}
	if url.RawQuery != location.RawQuery {
		return 0, false // does not match the pattern
	}
	for _, candidate := range otherEpnts {
		if candidate.URLAsString() != location.String() {
			continue // we're looking for the exact same URL
		}
		if candidate.Failure != "" {
			continue // we're looking for a success
		}
		// Assumption: we should already be using the same cookie names
		// since we're part of the same websteps step
		diff := analysisWebHTTPDiff(scoreID, epnt, candidate)
		if (diff & AnalysisHTTPDiff) != 0 {
			continue // there's still some difference so nope...
		}
		logcat.Emitf(logcat.NOTICE, logcat.CELEBRATE,
			"[#%d] it seems #%d is behind a proxy serving #%d to avoid a round trip",
			scoreID, epnt.ID, candidate.ID)
		return candidate.ID, true
	}
	return 0, false
}

// analysisRedirectLegitimateRedirect tries to detect a false positive
// case where the probe sees a redirect for a domain that is in the same
// public suffix of the original domain. For example, www.bing.com that
// redirects to cn.bing.com, but only if you're in China. So, if we notice
// that this is the case, we return true, otherwise we return false.
//
// For this condition to match, the left endpoint must be a redirect
// while the right endpoint must be 200 Ok.
//
// Note: on a purely speculative level, a censor could bypass this check
// by redirecting users to 404 pages of the censored website and we would
// not detect that. But AFAIK this does not happen and TBH I prefer to
// have a bit more false negatives than false positives.
func analysisRedirectLegitimateRedirect(
	scoreID int64, left, right *measurex.EndpointMeasurement) bool {
	if left.SeemsLegitimateRedirect() && right.StatusCode() == http.StatusOK {
		logcat.Emitf(logcat.NOTICE, logcat.SHRUG, "[#%d] however #%d seems a legitimate redirect %s",
			scoreID, left.ID, "so, we're going to treat it as such, not as #httpDiff")
		return true
	}
	return false
}
