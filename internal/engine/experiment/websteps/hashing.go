package websteps

//
// Hashing
//
// Comparison of bytes based on hashing
//

import (
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
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

// HashingBodies maps each body TLSH to its content.
type HashingBodies struct {
	Bodies map[string]*HashingBody `json:"bodies"`
}

// HashingBody represents a single hashed body.
type HashingBody struct {
	// ID is the unique ID of this body.
	ID int64 `json:"id"`

	// Refs contains the endpoint IDs that refer to this body.
	Refs []int64 `json:"refs"`

	// Truncated indicates whether the body is truncated.
	Truncated bool `json:"truncated"`

	// Body contains the real body.
	Body model.ArchivalMaybeBinaryData `json:"body"`
}

// buildHashingBodies constructs an HashingBodies structure from the
// overall result of a websteps measurement. We need this structure
// for comparing bodies to each other, remove false positives, and
// archiving a single copy of each body in the results.
//
// We limit our analysis to the bodies we have actually observed with
// the probe (i.e., we skip test helper bodies for which we know the
// hash but we don't know the real content).
//
// This function will always return an initialized HashingBodies
// pointer pointing to a valid initialized structure.
func (tk *TestKeys) buildHashingBodies(mx *measurex.Measurer) (hb *HashingBodies) {
	hb = &HashingBodies{
		Bodies: map[string]*HashingBody{},
	}
	for _, step := range tk.Steps {
		if step.ProbeInitial != nil {
			hb.fromEndpoints(mx, step.ProbeInitial.Endpoint)
		}
		// Note: ignore test helper hashes as documented
		hb.fromEndpoints(mx, step.ProbeAdditional)
	}
	return
}

// fromEndpoints fills this HashingBodies struct from the
// given list of endpoints (which may be empty.)
func (hb *HashingBodies) fromEndpoints(mx *measurex.Measurer,
	epnts []*measurex.EndpointMeasurement) {
	for _, epnt := range epnts {
		body := epnt.ResponseBody()
		if len(body) < 1 {
			continue // no point in tracking empty bodies
		}
		bh := epnt.ResponseBodyTLSH()
		if b, found := hb.Bodies[bh]; found {
			b.Refs = append(b.Refs, epnt.ID)
			continue
		}
		hb.Bodies[bh] = &HashingBody{
			ID:        mx.NextID(),
			Refs:      []int64{epnt.ID},
			Truncated: epnt.BodyIsTruncated(),
			Body: model.ArchivalMaybeBinaryData{
				Value: body,
			},
		}
	}
}
