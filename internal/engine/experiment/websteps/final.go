package websteps

//
// Final
//
// Contains code for final reprocessing.
//

import (
	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
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
			for _, epnt := range step.Analysis.TH {
				ExplainFlagsWithLogging(epnt, epnt.Flags)
			}
		}
	}
}
