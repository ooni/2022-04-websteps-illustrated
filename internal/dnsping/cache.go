package dnsping

import (
	"encoding/json"
	"path"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/caching"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
)

//
// Cache
//
// Contains a cache-on-disk implementation. Useful mainly to
// reproduce measurements in other systems for QA.
//

// Cache is a cache for dnsping measurements.
type Cache struct {
	// DisableNetwork allows to disable network operations.
	DisableNetwork bool

	// DNSPing is a reference to the underlying cache.
	DNSPing *caching.FSCache
}

// NewCache creates a new cache inside the given directory.
func NewCache(dirpath string) *Cache {
	p := path.Join(dirpath, "dnsping")
	return &Cache{
		DisableNetwork: false,
		DNSPing:        caching.NewFSCache(p),
	}
}

// CachingEngine is an Engine with caching.
type CachingEngine struct {
	// cache is the cache to use.
	cache *Cache

	// engine is the engine to use.
	engine AbstractEngine
}

// NewCachingEngine takes in input an existing engine and the
// cache and returns a new instance of CachingEngine.
func NewCachingMeasurer(ae AbstractEngine, cache *Cache) *CachingEngine {
	cae := &CachingEngine{
		cache:  cache,
		engine: ae,
	}
	return cae
}

var _ AbstractEngine = &CachingEngine{}

// NextID implements AbstractEngine.NextID.
func (cae *CachingEngine) NextID() int64 {
	return cae.engine.NextID()
}

// RunAsync implements AbstractEngine.RunAsync.
func (cae *CachingEngine) RunAsync(plans []*SinglePingPlan) <-chan *Result {
	out := make(chan *Result)
	go cae.run(plans, out)
	return out
}

func (cae *CachingEngine) run(plans []*SinglePingPlan, out chan<- *Result) {
	// 0. synchronize with parent
	defer close(out)
	// 1. find the cached measurements and return them
	var (
		todo  []*SinglePingPlan
		pings []*SinglePingResult
	)
	for _, plan := range plans {
		ping, found := cae.cache.FindSinglePingResult(plan)
		if !found {
			if cae.cache.DisableNetwork {
				logcat.Shrugf("dnsping: cache configured not to hit the network")
				pings = append(pings, &SinglePingResult{
					ID:              0,
					ResolverAddress: "",
					Delay:           0,
					Domain:          "",
					QueryType:       0,
					QueryID:         0,
					Query:           []byte{},
					Started:         time.Time{},
					Replies:         []*SinglePingReply{},
				})
				continue
			}
			todo = append(todo, plan)
			continue
		}
		ping.ID = cae.NextID()
		pings = append(pings, ping)
	}
	// 2. perform non-cached measurements and store them in cache
	meas := <-cae.engine.RunAsync(todo)
	if meas != nil { // not necessary now but added for future robustness
		for _, ping := range meas.Pings {
			_ = cae.cache.StoreSinglePingResult(ping)
			pings = append(pings, ping)
		}
	}
	// 3. write to parent
	out <- &Result{Pings: pings}
}

// FindSinglePingResult searches for a SinglePingResult compatible with the plan.
func (c *Cache) FindSinglePingResult(plan *SinglePingPlan) (*SinglePingResult, bool) {
	begin := time.Now()
	elist, _ := c.readSinglePingEntries(plan.summary())
	for _, entry := range elist {
		if !entry.couldDeriveFrom(plan) {
			continue // this entry has been generated from another plan
		}
		logcat.Cachef("cache: dnsping '%s' in %v", plan.summary(), time.Since(begin))
		return entry, true
	}
	return nil, false
}

// StoreSinglePingResult stores the given result into the cache.
func (c *Cache) StoreSinglePingResult(spr *SinglePingResult) error {
	elist, _ := c.readSinglePingEntries(spr.summary())
	var out []*SinglePingResult
	out = append(out, spr)
	for _, entry := range elist {
		if entry.isAnotherInstanceOf(spr) {
			continue // duplicate of the entry we've addeed
		}
		out = append(out, entry) // not a duplicate: keep
	}
	return c.writeSinglePingEntries(spr.summary(), out)
}

func (c *Cache) readSinglePingEntries(k string) ([]*SinglePingResult, bool) {
	data, err := c.DNSPing.Get(k)
	if err != nil {
		return nil, false
	}
	var elist []*SinglePingResult
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, false
	}
	return elist, true
}

func (c *Cache) writeSinglePingEntries(k string, o []*SinglePingResult) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.DNSPing.Set(k, data)
}
