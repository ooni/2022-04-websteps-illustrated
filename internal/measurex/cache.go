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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/rogpeppe/go-internal/lockedfile"
)

// simpleCache provides a simple cache-on-filesystem functionality.
type simpleCache struct {
	dirpath string
}

// newSimpleCache creates a new simpleCache instance.
func newSimpleCache(dirpath string) *simpleCache {
	return &simpleCache{dirpath: dirpath}
}

var _ model.KeyValueStore = &simpleCache{}

// Get implements KeyValueStore.Get.
func (sc *simpleCache) Get(key string) ([]byte, error) {
	_, fpath := sc.fsmap(key)
	return lockedfile.Read(fpath)
}

// Set implements KeyValueStore.Set.
func (sc *simpleCache) Set(key string, value []byte) error {
	dpath, fpath := sc.fsmap(key)
	const dperms = 0700
	if err := os.MkdirAll(dpath, dperms); err != nil {
		return err
	}
	const fperms = 0600
	return lockedfile.Write(fpath, bytes.NewReader(value), fperms)
}

// fsmap maps a given key to a directory and a file paths.
func (sc *simpleCache) fsmap(key string) (dpath, fpath string) {
	hs := sha256.Sum256([]byte(key))
	dpath = filepath.Join(sc.dirpath, fmt.Sprintf("%02x", hs[0]))
	fpath = filepath.Join(dpath, fmt.Sprintf("%02x-d", hs))
	return
}

func (sc *simpleCache) Trim() error {
	// TODO(bassosimone): implement this functionality.
	return nil
}

// Cache is a cache for measurex DNS and endpoint measurements.
type Cache struct {
	dns  *simpleCache
	epnt *simpleCache
}

// NewCache creates a new cache inside the given directory.
func NewCache(dirpath string) *Cache {
	ddp := path.Join(dirpath, "d") // dns
	edp := path.Join(dirpath, "e") // endpoint
	return &Cache{dns: newSimpleCache(ddp), epnt: newSimpleCache(edp)}
}

// Trim removes old entries from the cache.
func (c *Cache) Trim() {
	c.dns.Trim()
	c.epnt.Trim()
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

	// logger is the logger to use.
	logger model.Logger

	// measurer is the underlying measurer.
	measurer AbstractMeasurer

	// policy is the caching policy.
	policy CachingPolicy
}

// NewCachingMeasurer takes in input an existing measurer and the
// cache and returns a new instance of CachingMeasurer.
func NewCachingMeasurer(mx AbstractMeasurer, logger model.Logger,
	cache *Cache, policy CachingPolicy) *CachingMeasurer {
	cmx := &CachingMeasurer{
		cache:    cache,
		logger:   logger,
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
func (mx *CachingMeasurer) NewURLRedirectDeque(logger model.Logger) *URLRedirectDeque {
	return mx.measurer.NewURLRedirectDeque(logger)
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
		meas, found := mx.findDNSLookupMeasurement(plan)
		if !found {
			todo = append(todo, plan)
			continue
		}
		out <- meas
	}
	// 2. perform non-cached measurements and store them in cache
	for meas := range mx.measurer.DNSLookups(ctx, todo...) {
		_ = mx.storeDNSLookupMeasurement(meas)
		out <- meas
	}
}

// CachedDNSLookupMeasurement is the cached form of a DNSLookupMeasurement.
type CachedDNSLookupMeasurement struct {
	T time.Time
	M *DNSLookupMeasurement
}

func (mx *CachingMeasurer) findDNSLookupMeasurement(plan *DNSLookupPlan) (
	*DNSLookupMeasurement, bool) {
	begin := time.Now()
	elist, _ := mx.readDNSLookupEntry(plan.Domain)
	for _, entry := range elist {
		if entry.M == nil {
			continue // probably a corrupted entry
		}
		if !entry.M.CouldDeriveFrom(plan) {
			continue // this entry has been generated from another plan
		}
		if mx.policy.StaleDNSLookupMeasurement(&entry) {
			continue // stale entry we should eventually remove
		}
		mx.logger.Infof("👛 DNS lookup entry '%s' in %v", plan.Summary(), time.Since(begin))
		return entry.M, true
	}
	return nil, false
}

func (mx *CachingMeasurer) storeDNSLookupMeasurement(dlm *DNSLookupMeasurement) error {
	elist, _ := mx.readDNSLookupEntry(dlm.Domain())
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
	return mx.writeDNSLookupEntry(dlm.Domain(), out)
}

func (mx *CachingMeasurer) readDNSLookupEntry(k string) ([]CachedDNSLookupMeasurement, bool) {
	data, err := mx.cache.dns.Get(k)
	if err != nil {
		return nil, false
	}
	var elist []CachedDNSLookupMeasurement
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, false
	}
	return elist, true
}

func (mx *CachingMeasurer) writeDNSLookupEntry(k string, o []CachedDNSLookupMeasurement) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return mx.cache.dns.Set(k, data)
}

func (mx *CachingMeasurer) measureEndpoints(ctx context.Context,
	out chan<- *EndpointMeasurement, epnts ...*EndpointPlan) {
	// 0. synchronize with parent
	defer close(out)
	// 1. find the cached measurements and return them
	var todo []*EndpointPlan
	for _, plan := range epnts {
		meas, found := mx.findEndpointMeasurement(plan)
		if !found {
			todo = append(todo, plan)
			continue
		}
		out <- meas
	}
	// 2. perform non-cached measurements and store them in cache
	for meas := range mx.measurer.MeasureEndpoints(ctx, todo...) {
		_ = mx.storeEndpointMeasurement(meas)
		out <- meas
	}
}

// CachedEndpointMeasurement is the cached form of an EndpointMeasurement.
type CachedEndpointMeasurement struct {
	T time.Time
	M *EndpointMeasurement
}

func cacheCutLongString(s string) string {
	const toolong = 64
	if len(s) > toolong {
		s = s[:toolong] + " [...]"
	}
	return s
}

func (mx *CachingMeasurer) findEndpointMeasurement(
	plan *EndpointPlan) (*EndpointMeasurement, bool) {
	begin := time.Now()
	elist, _ := mx.readEndpointEntry(plan.Summary())
	for _, entry := range elist {
		if entry.M == nil {
			continue // probably a corrupted entry
		}
		if !entry.M.CouldDeriveFrom(plan) {
			continue // this entry has been generated from another plan
		}
		if mx.policy.StaleEndpointMeasurement(&entry) {
			continue // stale entry we should eventually remove
		}
		mx.logger.Infof("👛 endpoint entry '%s' in %v",
			cacheCutLongString(entry.M.Summary()), time.Since(begin))
		return entry.M, true
	}
	return nil, false
}

func (mx *CachingMeasurer) storeEndpointMeasurement(em *EndpointMeasurement) error {
	elist, _ := mx.readEndpointEntry(em.Summary())
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
	return mx.writeEndpointEntry(em.Summary(), out)
}

func (mx *CachingMeasurer) readEndpointEntry(k string) ([]CachedEndpointMeasurement, bool) {
	data, err := mx.cache.epnt.Get(k)
	if err != nil {
		return nil, false
	}
	var elist []CachedEndpointMeasurement
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, false
	}
	return elist, true
}

func (mx *CachingMeasurer) writeEndpointEntry(k string, o []CachedEndpointMeasurement) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return mx.cache.epnt.Set(k, data)
}
