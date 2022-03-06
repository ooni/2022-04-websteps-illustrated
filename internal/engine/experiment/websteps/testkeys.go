package websteps

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

//
// TestKeys
//
// Definition of the TestKeys struct.
//

// TestKeys contains a websteps measurement.
type TestKeys struct {
	// ProbeInitial contains the initial probe measurement.
	ProbeInitial *measurex.URLMeasurement

	// TH contains the response from the test helper.
	TH *THResponseWithID

	// ProbeAdditional contains additional measurements performed
	// by the probe using extra info from the TH.
	ProbeAdditional []*measurex.EndpointMeasurement

	// Analysis contains the results analysis.
	Analysis *TestKeysAnalysis
}

// TestKeysAnalysis contains the results of the analysis.
type TestKeysAnalysis struct {
	// DNS contains the DNS results analysis.
	DNS []*AnalysisDNS `json:"dns"`

	// Endpoint contains the endpoint results analysis.
	Endpoint []*AnalysisEndpoint `json:"endpoint"`
}

// THResponseWithID is a TH response with a ID assigned by the probe.
type THResponseWithID struct {
	// ID is the unique ID of this measurement.
	ID int64

	// DNS contains DNS measurements.
	DNS []*measurex.DNSLookupMeasurement

	// Endpoint contains the endpoints.
	Endpoint []*measurex.EndpointMeasurement
}

// ArchivalTestKeys is the archival data format for the TestKeys.
type ArchivalTestKeys struct {
	ProbeInitial    *measurex.ArchivalURLMeasurement       `json:"probe_initial"`
	TH              *ArchivalTHResponseWithID              `json:"th"`
	ProbeAdditional []measurex.ArchivalEndpointMeasurement `json:"probe_additional"`
	Analysis        *TestKeysAnalysis                      `json:"analysis"`
}

// ArchivalTHResponseWithID is the archival format of a TH response.
type ArchivalTHResponseWithID struct {
	ID       int64                                   `json:"id"`
	DNS      []measurex.ArchivalDNSLookupMeasurement `json:"dns"`
	Endpoint []measurex.ArchivalEndpointMeasurement  `json:"endpoint"`
}

// ToArchival converts a THResponse to its archival format.
func (r *THResponseWithID) ToArchival(begin time.Time) ArchivalTHResponseWithID {
	return ArchivalTHResponseWithID{
		ID:       r.ID,
		DNS:      measurex.NewArchivalDNSLookupMeasurementList(begin, r.DNS),
		Endpoint: measurex.NewArchivalEndpointMeasurementList(begin, r.Endpoint),
	}
}

// ToArchival converts test keys to the OONI archival data format.
func (tk *TestKeys) ToArchival(begin time.Time) *ArchivalTestKeys {
	if tk == nil {
		// just in case...
		return nil
	}
	out := &ArchivalTestKeys{}
	if tk.ProbeInitial != nil {
		v := tk.ProbeInitial.ToArchival(begin)
		out.ProbeInitial = &v
	}
	if tk.TH != nil {
		v := tk.TH.ToArchival(begin)
		out.TH = &v
	}
	if len(tk.ProbeAdditional) > 0 {
		out.ProbeAdditional = measurex.NewArchivalEndpointMeasurementList(
			begin, tk.ProbeAdditional)
	}
	out.Analysis = tk.Analysis
	return out
}

// newTestKeys creates a new TestKeys instance and uses
// the given URLMeasurement to initialize Discover.
func newTestKeys(discover *measurex.URLMeasurement) *TestKeys {
	return &TestKeys{
		ProbeInitial:    discover,
		TH:              &THResponseWithID{},
		ProbeAdditional: []*measurex.EndpointMeasurement{},
		Analysis:        &TestKeysAnalysis{},
	}
}
