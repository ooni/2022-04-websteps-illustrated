package measurex

//
// Cache
//
// Contains a measurement cache implementation. We cache DNS
// or endpoint measurements. There are two reasons:
//
// 1. avoid duplicating work in the TH;
//
// 2. record traces of what happened in the network using the
// probe and re-run these traces again by forcing the probe to
// use the cache to tune websteps analysis algorithms.
//

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/caching"
	"github.com/bassosimone/websteps-illustrated/internal/logcat"
)

// Cache is a cache for measurex DNS and endpoint measurements.
type Cache struct {
	// DisableNetwork allows to disable network operations.
	DisableNetwork bool

	// DNS is a reference to the underlying DNS cache.
	DNS *caching.FSCache

	// Endpoint is a reference to the underlying endpoint cache.
	Endpoint *caching.FSCache
}

// NewCache creates a new cache inside the given directory.
func NewCache(dirpath string) *Cache {
	ddp := path.Join(dirpath, "dns")
	edp := path.Join(dirpath, "endpoint")
	return &Cache{
		DisableNetwork: false,
		DNS:            caching.NewFSCache(ddp),
		Endpoint:       caching.NewFSCache(edp),
	}
}

// Trim removes old entries from the cache.
func (c *Cache) Trim() {
	c.DNS.Trim()
	c.Endpoint.Trim()
}

// StartTrimmer starts a background goroutine that runs until the
// given context is active and periodically trims the cache.
func (c *Cache) StartTrimmer(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Trim()
			}
		}
	}()
}

// CachingPolicy allows to customize che CachingMeasurer policy.
type CachingPolicy interface {
	// StaleDNSLookupMeasurement returns whether a DNSLookupMeasurement is stale.
	StaleDNSLookupMeasurement(m *CachedDNSLookupMeasurement) bool

	// StaleEndpointMeasurement returns whether an EndpointMeasurement is stale.
	StaleEndpointMeasurement(m *CachedEndpointMeasurement) bool
}

// CachingForeverPolicy returns a policy that caches entries forever.
func CachingForeverPolicy() CachingPolicy {
	return &cachingForeverPolicy{}
}

type cachingForeverPolicy struct{}

var _ CachingPolicy = &cachingForeverPolicy{}

func (*cachingForeverPolicy) StaleDNSLookupMeasurement(
	*CachedDNSLookupMeasurement) bool {
	return false
}

func (*cachingForeverPolicy) StaleEndpointMeasurement(
	*CachedEndpointMeasurement) bool {
	return false
}

// ReasonableCachingPolicy returns a reasonable caching policy.
func ReasonableCachingPolicy() CachingPolicy {
	return &reasonableCachingPolicy{}
}

type reasonableCachingPolicy struct{}

var _ CachingPolicy = &reasonableCachingPolicy{}

// cacheStaleTime is the time after which a record inaide an entry becomes stale.
const cacheStaleTime = 15 * time.Minute

func (*reasonableCachingPolicy) StaleDNSLookupMeasurement(m *CachedDNSLookupMeasurement) bool {
	return m == nil || time.Since(m.T) > cacheStaleTime
}

func (*reasonableCachingPolicy) StaleEndpointMeasurement(m *CachedEndpointMeasurement) bool {
	return m == nil || time.Since(m.T) > cacheStaleTime
}

// CachingMeasurer is a measurer using a local cache.
//
// The cache works as follows:
//
// 1. it stores all the DNS lookup measurements using the same
// target domain into the same bucket and checks for equality
// using a strict definition of equality that includes not only
// the domain but also the lookup type to distinguish between
// similar DNS lookups for the same domain.
//
// 2. it stores all the endpoint measurements using as key their
// summary, which should avoid creating too large buckets.
//
// On disk, the cache stores a list of records having the same
// ~unique sha256. Even when there should only be a single record
// with a given identifier (unlikely for domains but much more
// likely for endpoints) we use a list on disk just in case
// there's going to be any hash collision.
type CachingMeasurer struct {
	// cache is the underlying cache.
	cache *Cache

	// measurer is the underlying measurer.
	measurer AbstractMeasurer

	// policy is the caching policy.
	policy CachingPolicy
}

// NewCachingMeasurer takes in input an existing measurer and the
// cache and returns a new instance of CachingMeasurer.
func NewCachingMeasurer(mx AbstractMeasurer,
	cache *Cache, policy CachingPolicy) *CachingMeasurer {
	cmx := &CachingMeasurer{
		cache:    cache,
		measurer: mx,
		policy:   policy,
	}
	return cmx
}

var _ AbstractMeasurer = &CachingMeasurer{}

// DNSLookups implements AbstractMeasurer.DNSLookups.
func (mx *CachingMeasurer) DNSLookups(ctx context.Context,
	dnsLookups ...*DNSLookupPlan) <-chan *DNSLookupMeasurement {
	out := make(chan *DNSLookupMeasurement)
	go mx.dnsLookups(ctx, out, dnsLookups...)
	return out
}

// FlattenOptions implements AbstractMeasurer.FlattenOptions.
func (mx *CachingMeasurer) FlattenOptions() *Options {
	return mx.measurer.FlattenOptions()
}

// MeasureEndpoints implements AbstractMeasurer.MeasureEndpoints.
func (mx *CachingMeasurer) MeasureEndpoints(ctx context.Context,
	epnts ...*EndpointPlan) <-chan *EndpointMeasurement {
	out := make(chan *EndpointMeasurement)
	go mx.measureEndpoints(ctx, out, epnts...)
	return out
}

// NewURLMeasurement implements AbstractMeasurer.NewURLMeasurement.
func (mx *CachingMeasurer) NewURLMeasurement(input string) (*URLMeasurement, error) {
	return mx.measurer.NewURLMeasurement(input)
}

// NewURLRedirectDeque implements AbstractMeasurer.NewURLRedirectDeque.
func (mx *CachingMeasurer) NewURLRedirectDeque() *URLRedirectDeque {
	return mx.measurer.NewURLRedirectDeque()
}

// NextID implements AbstractMeasurer.NextID.
func (mx *CachingMeasurer) NextID() int64 {
	return mx.measurer.NextID()
}

// Redirects implements AbstractMeasurer.Redirects.
func (mx *CachingMeasurer) Redirects(epnts []*EndpointMeasurement,
	opts *Options) ([]*URLMeasurement, bool) {
	return mx.measurer.Redirects(epnts, opts)
}

func (mx *CachingMeasurer) dnsLookups(ctx context.Context,
	out chan<- *DNSLookupMeasurement, dnsLookups ...*DNSLookupPlan) {
	// 0. synchronize with parent
	defer close(out)
	// 1. find the cached measurements and return them
	var todo []*DNSLookupPlan
	for _, plan := range dnsLookups {
		meas, found := mx.cache.FindDNSLookupMeasurement(plan, mx.policy)
		if !found {
			if mx.cache.DisableNetwork {
				logcat.Shrugf("measurex: cache miss for: %s", plan.Summary())
				out <- &DNSLookupMeasurement{
					ID:               0,
					URLMeasurementID: 0,
					ReverseAddress:   "",
					Lookup:           &archival.FlatDNSLookupEvent{},
					RoundTrip:        []*archival.FlatDNSRoundTripEvent{},
				}
				continue
			}
			todo = append(todo, plan)
			continue
		}
		out <- meas
	}
	// 2. perform non-cached measurements and store them in cache
	for meas := range mx.measurer.DNSLookups(ctx, todo...) {
		_ = mx.cache.StoreDNSLookupMeasurement(meas)
		out <- meas
	}
}

// CachedDNSLookupMeasurement is the cached form of a DNSLookupMeasurement.
type CachedDNSLookupMeasurement struct {
	T time.Time
	M *DNSLookupMeasurement
}

// FindDNSLookupMeasurement searches for a DNSLookupMeasurement compatible with the plan.
func (c *Cache) FindDNSLookupMeasurement(
	plan *DNSLookupPlan, policy CachingPolicy) (*DNSLookupMeasurement, bool) {
	begin := time.Now()
	logcat.Emitf(logcat.DEBUG, logcat.CACHE, "cache: searching for %s", plan.Summary())
	elist, _ := c.readDNSLookupEntry(plan.Domain)
	for _, entry := range elist {
		if entry.M == nil {
			logcat.Emit(logcat.DEBUG, logcat.CACHE, "cache: entry.M is nil")
			continue // probably a corrupted entry
		}
		if !entry.M.CouldDeriveFrom(plan) {
			logcat.Emitf(logcat.DEBUG, logcat.CACHE,
				"cache: entry %s does not derive from plan", entry.M.Summary())
			continue // this entry has been generated from another plan
		}
		if policy.StaleDNSLookupMeasurement(&entry) {
			logcat.Emitf(
				logcat.DEBUG, logcat.CACHE, "cache: entry %s is stale", entry.M.Summary())
			continue // stale entry we should eventually remove
		}
		logcat.Cachef("cache: DNS lookup entry '%s' in %v", plan.Summary(), time.Since(begin))
		return entry.M, true
	}
	logcat.Emitf(logcat.DEBUG, logcat.CACHE, "cache: no entry for %s", plan.Summary())
	return nil, false
}

// StoreDNSLookupMeasurement stores the given measurement into the cache.
func (c *Cache) StoreDNSLookupMeasurement(dlm *DNSLookupMeasurement) error {
	elist, _ := c.readDNSLookupEntry(dlm.Domain())
	var out []CachedDNSLookupMeasurement
	out = append(out, CachedDNSLookupMeasurement{ // fast search: new entry at the beginning
		T: time.Now(),
		M: dlm,
	})
	for _, entry := range elist {
		if entry.M == nil {
			continue // remove this corrupted entry
		}
		if entry.M.IsAnotherInstanceOf(dlm) {
			continue // duplicate of the entry we've addeed
		}
		out = append(out, entry) // not a duplicate and not corrupted: keep
	}
	return c.writeDNSLookupEntry(dlm.Domain(), out)
}

func (c *Cache) readDNSLookupEntry(k string) ([]CachedDNSLookupMeasurement, bool) {
	data, err := c.DNS.Get(k)
	if err != nil {
		return nil, false
	}
	var elist []CachedDNSLookupMeasurement
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, false
	}
	return elist, true
}

func (c *Cache) writeDNSLookupEntry(k string, o []CachedDNSLookupMeasurement) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.DNS.Set(k, data)
}

func (mx *CachingMeasurer) measureEndpoints(ctx context.Context,
	out chan<- *EndpointMeasurement, epnts ...*EndpointPlan) {
	// 0. synchronize with parent
	defer close(out)
	// 1. find the cached measurements and return them
	var todo []*EndpointPlan
	for _, plan := range epnts {
		meas, found := mx.cache.FindEndpointMeasurement(plan, mx.policy)
		if !found {
			if mx.cache.DisableNetwork {
				logcat.Shrugf("measurex: cache miss for: %s", plan.Summary())
				out <- &EndpointMeasurement{
					ID:               0,
					URLMeasurementID: 0,
					URL:              &SimpleURL{},
					Network:          "",
					Address:          "",
					Options:          &Options{},
					OrigCookies:      []*http.Cookie{},
					Failure:          "",
					FailedOperation:  "",
					NewCookies:       []*http.Cookie{},
					Location:         &SimpleURL{},
					HTTPTitle:        "",
					NetworkEvent:     []*archival.FlatNetworkEvent{},
					TCPConnect:       &archival.FlatNetworkEvent{},
					QUICTLSHandshake: &archival.FlatQUICTLSHandshakeEvent{},
					HTTPRoundTrip:    &archival.FlatHTTPRoundTripEvent{},
				}
				continue
			}
			todo = append(todo, plan)
			continue
		}
		out <- meas
	}
	// 2. perform non-cached measurements and store them in cache
	for meas := range mx.measurer.MeasureEndpoints(ctx, todo...) {
		_ = mx.cache.StoreEndpointMeasurement(meas)
		out <- meas
	}
}

// CachedEndpointMeasurement is the cached form of an EndpointMeasurement.
type CachedEndpointMeasurement struct {
	T time.Time
	M *EndpointMeasurement
}

// FindEndpointMeasurement finds the endpoint measurement deriving from the given plan.
func (c *Cache) FindEndpointMeasurement(
	plan *EndpointPlan, policy CachingPolicy) (*EndpointMeasurement, bool) {
	begin := time.Now()
	logcat.Emitf(logcat.DEBUG, logcat.CACHE, "cache: searching for %s", plan.Summary())
	elist, _ := c.readEndpointEntry(plan.Summary())
	for _, entry := range elist {
		if entry.M == nil {
			logcat.Emit(logcat.DEBUG, logcat.CACHE, "cache: entry.M is nil")
			continue // probably a corrupted entry
		}
		if !entry.M.CouldDeriveFrom(plan) {
			logcat.Emitf(logcat.DEBUG, logcat.CACHE,
				"cache: entry %s does not derive from plan", entry.M.Summary())
			continue // this entry has been generated from another plan
		}
		if policy.StaleEndpointMeasurement(&entry) {
			logcat.Emitf(
				logcat.DEBUG, logcat.CACHE, "cache: entry %s is stale", entry.M.Summary())
			continue // stale entry we should eventually remove
		}
		logcat.Cachef("cache: endpoint entry in %v: %s", time.Since(begin), entry.M.Summary())
		return entry.M, true
	}
	logcat.Emitf(logcat.DEBUG, logcat.CACHE, "cache: no entry for %s", plan.Summary())
	return nil, false
}

// StoreEndpointMeasurement stores the given measurement in cache.
func (c *Cache) StoreEndpointMeasurement(em *EndpointMeasurement) error {
	elist, _ := c.readEndpointEntry(em.Summary())
	var out []CachedEndpointMeasurement
	out = append(out, CachedEndpointMeasurement{ // fast search: new entry at the beginning
		T: time.Now(),
		M: em,
	})
	for _, entry := range elist {
		if entry.M == nil {
			continue // remove this corrupted entry
		}
		if em.IsAnotherInstanceOf(entry.M) {
			continue // duplicate of the entry we've added
		}
		out = append(out, entry) // not a duplicate and not corrupted: keep
	}
	return c.writeEndpointEntry(em.Summary(), out)
}

func (c *Cache) readEndpointEntry(k string) ([]CachedEndpointMeasurement, bool) {
	data, err := c.Endpoint.Get(k)
	if err != nil {
		return nil, false
	}
	var elist []CachedEndpointMeasurement
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, false
	}
	return elist, true
}

func (c *Cache) writeEndpointEntry(k string, o []CachedEndpointMeasurement) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.Endpoint.Set(k, data)
}
