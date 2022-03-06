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
	// Discover contains the URLMeasurement performed by the
	// probe during the "discover" step.
	Discover *measurex.URLMeasurement

	// TH contains the response from the test helper.
	TH *THResponseWithID
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
	Discover *measurex.ArchivalURLMeasurement `json:"discover"`
	TH       *ArchivalTHResponseWithID        `json:"th"`
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
	if tk.Discover != nil {
		v := tk.Discover.ToArchival(begin)
		out.Discover = &v
	}
	if tk.TH != nil {
		v := tk.TH.ToArchival(begin)
		out.TH = &v
	}
	return out
}

// newTestKeys creates a new TestKeys instance and uses
// the given URLMeasurement to initialize Discover.
func newTestKeys(discover *measurex.URLMeasurement) *TestKeys {
	return &TestKeys{
		Discover: discover,
	}
}

// rememberVisitedURLs inspects all the URLs visited by the
// probe and stores them into the redirect deque.
func (tk *TestKeys) rememberVisitedURLs(q *measurex.URLRedirectDeque) {
	// nothing for now
}

// redirects computes all the redirects from all the results
// that are stored inside the test keys.
func (tk *TestKeys) redirects(mx *measurex.Measurer) ([]*measurex.URLMeasurement, bool) {
	// nothing for now
	return nil, false
}

// analyzeResults computes the probe's analysis of the results.
func (tk *TestKeys) analyzeResults(logger model.Logger) {
	logger.Infof("🧐 analyzing the results")
	// nothing for now
}
