package websteps

//
// Archival
//
// Code to generate the archival data format.
//

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/dnsping"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// ArchivalTestKeys contains the archival test keys.
type ArchivalTestKeys struct {
	URL   string                           `json:"url"`
	Steps []*ArchivalSingleStepMeasurement `json:"steps"`
	Flags int64                            `json:"flags"`
}

// ToArchival converts TestKeys to the archival data format.
func (tk *TestKeys) ToArchival(begin time.Time) (out *ArchivalTestKeys) {
	out = &ArchivalTestKeys{
		URL:   tk.URL,
		Steps: []*ArchivalSingleStepMeasurement{}, // later
		Flags: tk.Flags,
	}
	for _, entry := range tk.Steps {
		out.Steps = append(out.Steps, entry.ToArchival(begin))
	}
	return
}

// ArchivalSingleStepMeasurement is the archival data format
// for a SingleStepMeasurement.
type ArchivalSingleStepMeasurement struct {
	// Initial measurement by the probe
	ID          int64                                   `json:"id"`
	EndpointIDs []int64                                 `json:"endpoint_ids"`
	URL         string                                  `json:"url"`
	Cookies     []string                                `json:"cookies"`
	DNS         []measurex.ArchivalDNSLookupMeasurement `json:"dns"`
	Endpoint    []measurex.ArchivalEndpointMeasurement  `json:"endpoint"`

	// Data gathered by the TH or follow-up experiments
	TH              *ArchivalTHResponse                    `json:"th"`
	DNSPing         *dnsping.ArchivalResult                `json:"dnsping"`
	ProbeAdditional []measurex.ArchivalEndpointMeasurement `json:"probe_additional"`

	// Overall analysis of this step
	Analysis *Analysis `json:"analysis"`
	Flags    int64     `json:"flags"`
}

// ArchivalTHResponse is the archival format of a TH response.
type ArchivalTHResponse struct {
	DNS      []measurex.ArchivalDNSLookupMeasurement `json:"dns"`
	Endpoint []measurex.ArchivalEndpointMeasurement  `json:"endpoint"`
}

// ToArchival converts test keys to the OONI archival data format.
func (ssm *SingleStepMeasurement) ToArchival(begin time.Time) *ArchivalSingleStepMeasurement {
	if ssm == nil {
		logcat.Bugf("trying to archive an nil SingleStepMeasurement")
		return nil
	}
	if ssm.ProbeInitial == nil {
		logcat.Bugf("ssm.ProbeInitial should never be nil")
		return nil
	}
	// Note: we're serializing the bodies inline. In the future we
	// may want to use locality-sensitive hashing and only send a
	// single copy of each body. We need to figure out which specific
	// kind of hashing to use for this purpose first.
	const bodyFlags = 0
	v := ssm.ProbeInitial.ToArchival(begin, bodyFlags)
	out := &ArchivalSingleStepMeasurement{
		ID:              v.ID,
		EndpointIDs:     v.EndpointIDs,
		URL:             v.URL,
		Cookies:         v.Cookies,
		DNS:             v.DNS,
		Endpoint:        v.Endpoint,
		TH:              nil, // later
		DNSPing:         nil, // later
		ProbeAdditional: nil, // later
		Analysis:        nil, // later
		Flags:           ssm.Flags,
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
