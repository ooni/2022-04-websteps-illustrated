package websteps

//
// SingleStepMeasurement
//
// Definition of the SingleStepMeasurement struct.
//

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/dnsping"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// SingleStepMeasurement contains a a single-step measurement.
type SingleStepMeasurement struct {
	// ProbeInitial contains the initial probe measurement.
	ProbeInitial *measurex.URLMeasurement

	// TH contains the response from the test helper.
	TH *THResponseWithID

	// DNSPing contains the optional result of
	// the dnsping follow-up experiment.
	DNSPing *dnsping.Result

	// ProbeAdditional contains additional measurements performed
	// by the probe using extra info from the TH.
	ProbeAdditional []*measurex.EndpointMeasurement

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
	TH              *ArchivalTHResponse                    `json:"th"`
	DNSPing         *dnsping.ArchivalResult                `json:"dnsping"`
	ProbeAdditional []measurex.ArchivalEndpointMeasurement `json:"probe_additional"`
	Analysis        *Analysis                              `json:"analysis"`
	Flags           int64                                  `json:"flags"`
}

// ArchivalTHResponse is the archival format of a TH response.
type ArchivalTHResponse struct {
	DNS      []measurex.ArchivalDNSLookupMeasurement `json:"dns"`
	Endpoint []measurex.ArchivalEndpointMeasurement  `json:"endpoint"`
}

// ToArchival converts a THResponse to its archival format.
func (r *THResponseWithID) ToArchival(begin time.Time) ArchivalTHResponse {
	// Here it's fine to pass empty flags because we're serializing
	// the TH response which does not contain the body
	const bodyFlags = 0
	return ArchivalTHResponse{
		DNS: measurex.NewArchivalDNSLookupMeasurementList(begin, r.DNS),
		Endpoint: measurex.NewArchivalEndpointMeasurementList(
			begin, r.Endpoint, bodyFlags),
	}
}

// ToArchival converts test keys to the OONI archival data format.
func (ssm *SingleStepMeasurement) ToArchival(begin time.Time) *ArchivalSingleStepMeasurement {
	if ssm == nil {
		// just in case...
		return nil
	}
	// Note: we're serializing the body choosing the option to
	// serialize its hash rather than the body content
	const bodyFlags = model.ArchivalHTTPBodySerializeTLSH
	out := &ArchivalSingleStepMeasurement{}
	if ssm.ProbeInitial != nil {
		v := ssm.ProbeInitial.ToArchival(begin, bodyFlags)
		out.ProbeInitial = &v
	}
	if ssm.TH != nil {
		v := ssm.TH.ToArchival(begin)
		out.TH = &v
	}
	if ssm.DNSPing != nil {
		out.DNSPing = ssm.DNSPing.ToArchival(begin)
	}
	if len(ssm.ProbeAdditional) > 0 {
		out.ProbeAdditional = measurex.NewArchivalEndpointMeasurementList(
			begin, ssm.ProbeAdditional, bodyFlags)
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
