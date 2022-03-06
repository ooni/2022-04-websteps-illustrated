package websteps

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
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
	return out
}

// newTestKeys creates a new TestKeys instance and uses
// the given URLMeasurement to initialize Discover.
func newTestKeys(discover *measurex.URLMeasurement) *TestKeys {
	return &TestKeys{
		ProbeInitial: discover,
	}
}

// rememberVisitedURLs inspects all the URLs visited by the
// probe and stores them into the redirect deque.
func (tk *TestKeys) rememberVisitedURLs(q *measurex.URLRedirectDeque) {
	if tk.ProbeInitial != nil {
		q.RememberVisitedURLs(tk.ProbeInitial.Endpoint)
	}
	q.RememberVisitedURLs(tk.ProbeAdditional)
}

// redirects computes all the redirects from all the results
// that are stored inside the test keys.
func (tk *TestKeys) redirects(mx *measurex.Measurer) (o []*measurex.URLMeasurement, v bool) {
	if tk.ProbeInitial != nil {
		o, _ = mx.Redirects(tk.ProbeInitial.Endpoint, tk.ProbeInitial.Options)
	}
	r, _ := mx.Redirects(tk.ProbeAdditional, tk.ProbeInitial.Options)
	o = append(o, r...)
	return o, len(o) > 0
}

// analyzeResults computes the probe's analysis of the results.
func (tk *TestKeys) analyzeResults(logger model.Logger) {
	logger.Infof("🔬 analyzing the results")
	// nothing for now
}
