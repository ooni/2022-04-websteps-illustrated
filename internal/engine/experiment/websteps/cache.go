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

	// pa contains the IP addrs used by the probe.
	pa map[string]bool

	// ual contains the list of URLAddress we've visited. We expect this
	// list to be reasonably short, so O(N) is fine.
	ual []*measurex.URLAddress
}

// newStepsCache creates a new StepsCache instance.
func newStepsCache() *stepsCache {
	return &stepsCache{
		mu:  sync.Mutex{},
		pa:  map[string]bool{},
		ual: []*measurex.URLAddress{},
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
	sc.updateUsedAddrsLocked(ssm)
	plu, _ := ssm.probeInitialURLAddressList()
	discu, _ := ssm.testHelperOrDNSPingURLAddressList()
	domain := ssm.ProbeInitialDomain()
	xu, _ := measurex.EndpointMeasurementListToURLAddressList(domain, ssm.ProbeAdditional...)
	// The merge will be stable, i.e., it will preseve the relative order with which
	// IP addrs first appear. This implies that the next steps using sc.ual will first
	// see the IP addrs in plu first, then the ones inside plu, etc.
	sc.ual = measurex.MergeURLAddressListStable(sc.ual, plu, discu, xu)
}

func (sc *stepsCache) updateUsedAddrsLocked(ssm *SingleStepMeasurement) {
	if ssm.ProbeInitial != nil {
		for _, epnt := range ssm.ProbeInitial.Endpoint {
			if ipAddr := epnt.IPAddress(); ipAddr != "" {
				sc.pa[ipAddr] = true
			}
		}
	}
	for _, epnt := range ssm.ProbeAdditional {
		if ipAddr := epnt.IPAddress(); ipAddr != "" {
			sc.pa[ipAddr] = true
		}
	}
}

// dnsLookup performs a DNS lookup for the given domain using the cache.
func (sc *stepsCache) dnsLookup(mx measurex.AbstractMeasurer,
	urlMeasurementID int64, domain string) (*measurex.DNSLookupMeasurement, bool) {
	defer sc.mu.Unlock()
	sc.mu.Lock()
	var (
		flags int64
		addrs []string
	)
	for _, e := range sc.ual {
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
	// TODO(bassosimone): here we can probably use a factory.
	o := &measurex.DNSLookupMeasurement{
		ID:               mx.NextID(),
		URLMeasurementID: urlMeasurementID,
		ReverseAddress:   "",
		Lookup: &archival.FlatDNSLookupEvent{
			ALPNs:           alpns,
			Addresses:       addrs,
			CNAME:           "",
			Domain:          domain,
			Failure:         "",
			Finished:        now,
			LookupType:      archival.DNSLookupTypeHTTPS,
			NS:              []string{},
			PTRs:            []string{},
			ResolverAddress: "dnscache",
			ResolverNetwork: "",
			Started:         now,
		},
		RoundTrip: []*archival.FlatDNSRoundTripEvent{},
	}
	return o, true
}

// prioritizeKnownAddrs rewrites the candidate URL address list we'll use
// for measuring endpoints to move addrs we already used towards the beginning of
// the list. We want to reuse the same addrs for subsequent measurements to
// construct more realistic-looking redirect chains.
func (sc *stepsCache) prioritizeKnownAddrs(in []*measurex.URLAddress) []*measurex.URLAddress {
	defer sc.mu.Unlock()
	sc.mu.Lock()
	used := []*measurex.URLAddress{}
	unused := []*measurex.URLAddress{}
	for _, e := range in {
		if _, found := sc.pa[e.Address]; !found {
			unused = append(unused, e)
		} else {
			used = append(used, e)
		}
	}
	o := append(used, unused...)
	return o
}
