package websteps

//
// SingleStepMeasurement
//
// Definition of the SingleStepMeasurement struct.
//

import (
	"github.com/bassosimone/websteps-illustrated/internal/dnsping"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// SingleStepMeasurement contains a a single-step measurement.
type SingleStepMeasurement struct {
	// ProbeInitial contains the initial probe measurement.
	ProbeInitial *measurex.URLMeasurement

	// TH contains the response from the test helper.
	TH *THResponse `json:",omitempty"`

	// DNSPing contains the optional result of
	// the dnsping follow-up experiment.
	DNSPing *dnsping.Result `json:",omitempty"`

	// ProbeAdditional contains additional measurements performed
	// by the probe using extra info from the TH.
	ProbeAdditional []*measurex.EndpointMeasurement `json:",omitempty"`

	// Analysis contains the results analysis.
	Analysis *Analysis

	// Flags contains aggregate flags for this single step.
	Flags int64
}

// ProbeInitialURLMeasurementID returns the ProbeInitial.ID value or zero.
func (ssm *SingleStepMeasurement) ProbeInitialURLMeasurementID() int64 {
	if ssm.ProbeInitial != nil {
		return ssm.ProbeInitial.ID
	}
	return 0
}

// ProbeInitialDomain returns the domain of ProbeInitial.Domain() or zero.
func (ssm *SingleStepMeasurement) ProbeInitialDomain() string {
	if ssm.ProbeInitial != nil {
		return ssm.ProbeInitial.Domain()
	}
	return ""
}

// newSingleStepMeasurement creates a new SingleStepMeasurement and uses
// the given URLMeasurement to initialize Discover.
func newSingleStepMeasurement(discover *measurex.URLMeasurement) *SingleStepMeasurement {
	return &SingleStepMeasurement{
		ProbeInitial:    discover,
		TH:              &THResponse{},
		ProbeAdditional: []*measurex.EndpointMeasurement{},
		Analysis:        &Analysis{},
	}
}
