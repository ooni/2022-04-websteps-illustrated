package baseline

//
// Contains code to generate the archival data format.
//

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// ArchivalTestKeys contains the archival TestKeys.
type ArchivalTestKeys struct {
	DNS   measurex.ArchivalDNSLookupMeasurement `json:"dns"`
	HTTPS measurex.ArchivalEndpointMeasurement  `json:"https"`
	HTTP  measurex.ArchivalEndpointMeasurement  `json:"http"`
}

// ToArchival generates the archival TestKeys.
func (tk *TestKeys) ToArchival(begin time.Time) *ArchivalTestKeys {
	return &ArchivalTestKeys{
		DNS:   tk.DNS.ToArchival(begin),
		HTTPS: tk.HTTPS.ToArchival(begin, 0),
		HTTP:  tk.HTTP.ToArchival(begin, 0),
	}
}
