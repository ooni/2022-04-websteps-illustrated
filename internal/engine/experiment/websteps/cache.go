package websteps

//
// Cache
//
// This file contains caching code.
//

import (
	"sync"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// stepsCache contains a cache common to all steps. This structure
// is data race safe through the use of a mutex.
type stepsCache struct {
	// mu is the mutex we're using.
	mu sync.Mutex

	// uas contains the list of URLAddress we've visited. We expect this
	// list to be reasonably short, so O(N) is fine.
	uas []*measurex.URLAddress
}

// newStepsCache creates a new StepsCache instance.
func newStepsCache() *stepsCache {
	return &stepsCache{
		mu:  sync.Mutex{},
		uas: []*measurex.URLAddress{},
	}
}

// update updates the internals of the cache using the results
// of a single step (i.e., a SingleStepMeasurement).
func (sc *stepsCache) update(ssm *SingleStepMeasurement) {
	defer sc.mu.Unlock()
	sc.mu.Lock()
	if ssm == nil {
		return // just in case
	}
	plu, _ := ssm.probeInitialURLAddressList()
	discu, _ := ssm.testHelperOrDNSPingURLAddressList()
	domain := ssm.ProbeInitialDomain()
	xu, _ := measurex.EndpointMeasurementListToURLAddressList(domain, ssm.ProbeAdditional...)
	// The merge will be stable, i.e., it will preseve the relative order with which
	// IP addrs first appear. This implies that the next steps using sc.uas will first
	// see the IP addrs in plu first, then the ones inside plu, etc.
	sc.uas = measurex.MergeURLAddressListStable(sc.uas, plu, discu, xu)
}

// dnsLookup performs a DNS lookup for the given domain using the cache.
func (sc *stepsCache) dnsLookup(mx *measurex.Measurer,
	urlMeasurementID int64, domain string) (*measurex.DNSLookupMeasurement, bool) {
	defer sc.mu.Unlock()
	sc.mu.Lock()
	var (
		flags int64
		addrs []string
	)
	for _, e := range sc.uas {
		if domain != e.Domain {
			continue // this entry is not relevant
		}
		flags |= e.Flags
		addrs = append(addrs, e.Address)
	}
	if len(addrs) < 1 {
		return nil, false
	}
	var alpns []string
	if (flags & measurex.URLAddressSupportsHTTP3) != 0 {
		alpns = append(alpns, "h3")
	}
	now := time.Now()
	o := &measurex.DNSLookupMeasurement{
		ID:               mx.NextID(),
		URLMeasurementID: urlMeasurementID,
		Lookup: &archival.FlatDNSLookupEvent{
			ALPNs:           alpns,
			Addresses:       addrs,
			Domain:          domain,
			Failure:         "",
			Finished:        now,
			LookupType:      archival.DNSLookupTypeHTTPS,
			ResolverAddress: "dnscache",
			ResolverNetwork: "",
			Started:         now,
		},
		RoundTrip: []*archival.FlatDNSRoundTripEvent{},
	}
	return o, true
}
