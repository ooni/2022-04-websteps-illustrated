package websteps

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

//
// SingleStepMeasurement
//
// Definition of the SingleStepMeasurement struct.
//

// SingleStepMeasurement contains a a single-step measurement.
type SingleStepMeasurement struct {
	// ProbeInitial contains the initial probe measurement.
	ProbeInitial *measurex.URLMeasurement

	// TH contains the response from the test helper.
	TH *THResponseWithID

	// ProbeAdditional contains additional measurements performed
	// by the probe using extra info from the TH.
	ProbeAdditional []*measurex.EndpointMeasurement

	// Analysis contains the results analysis.
	Analysis *Analysis
}

// Analysis contains the results of the analysis.
type Analysis struct {
	// DNS contains the DNS results analysis.
	DNS []*AnalysisDNS `json:"dns"`

	// Endpoint contains the endpoint results analysis.
	Endpoint []*AnalysisEndpoint `json:"endpoint"`
}

// THResponseWithID is a TH response with a ID assigned by the probe.
type THResponseWithID struct {
	// id is the unique ID of the original URLMeasurement.
	id int64

	// DNS contains DNS measurements.
	DNS []*measurex.DNSLookupMeasurement

	// Endpoint contains the endpoints.
	Endpoint []*measurex.EndpointMeasurement
}

// ArchivalSingleStepMeasurement is the archival data format
// for SingleStepMeasurement.
type ArchivalSingleStepMeasurement struct {
	ProbeInitial    *measurex.ArchivalURLMeasurement       `json:"probe_initial"`
	TH              *ArchivalTHResponseWithID              `json:"th"`
	ProbeAdditional []measurex.ArchivalEndpointMeasurement `json:"probe_additional"`
	Analysis        *Analysis                              `json:"analysis"`
}

// ArchivalTHResponseWithID is the archival format of a TH response.
type ArchivalTHResponseWithID struct {
	DNS      []measurex.ArchivalDNSLookupMeasurement `json:"dns"`
	Endpoint []measurex.ArchivalEndpointMeasurement  `json:"endpoint"`
}

// ToArchival converts a THResponse to its archival format.
func (r *THResponseWithID) ToArchival(begin time.Time) ArchivalTHResponseWithID {
	return ArchivalTHResponseWithID{
		DNS:      measurex.NewArchivalDNSLookupMeasurementList(begin, r.DNS),
		Endpoint: measurex.NewArchivalEndpointMeasurementList(begin, r.Endpoint),
	}
}

// ToArchival converts test keys to the OONI archival data format.
func (ssm *SingleStepMeasurement) ToArchival(begin time.Time) *ArchivalSingleStepMeasurement {
	if ssm == nil {
		// just in case...
		return nil
	}
	out := &ArchivalSingleStepMeasurement{}
	if ssm.ProbeInitial != nil {
		v := ssm.ProbeInitial.ToArchival(begin)
		out.ProbeInitial = &v
	}
	if ssm.TH != nil {
		v := ssm.TH.ToArchival(begin)
		out.TH = &v
	}
	if len(ssm.ProbeAdditional) > 0 {
		out.ProbeAdditional = measurex.NewArchivalEndpointMeasurementList(
			begin, ssm.ProbeAdditional)
	}
	out.Analysis = ssm.Analysis
	return out
}

// newSingleStepMeasurement creates a new SingleStepMeasurement and uses
// the given URLMeasurement to initialize Discover.
func newSingleStepMeasurement(discover *measurex.URLMeasurement) *SingleStepMeasurement {
	return &SingleStepMeasurement{
		ProbeInitial:    discover,
		TH:              &THResponseWithID{},
		ProbeAdditional: []*measurex.EndpointMeasurement{},
		Analysis:        &Analysis{},
	}
}
