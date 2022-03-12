package websteps

//
// Hashing
//
// Comparison of bytes based on hashing
//

import (
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/glaslos/tlsh"
)

// endpointHashingTLSHCompareBodies returns the score comparison of the
// bodies using TLSH hashing. The return value is either a valid score
// and true, on success, or zero and false, on failure.
func (ssm *SingleStepMeasurement) endpointHashingTLSHCompareBodies(
	pe, the *measurex.EndpointMeasurement) (int, bool) {
	peh, err := tlsh.ParseStringToTlsh(pe.ResponseBodyTLSH())
	if err != nil {
		return 0, false
	}
	theh, err := tlsh.ParseStringToTlsh(the.ResponseBodyTLSH())
	if err != nil {
		return 0, false
	}
	return peh.Diff(theh), true
}
