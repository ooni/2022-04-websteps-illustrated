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
	"log"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/cachex"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

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
// 2. it stores all the endpoint measurements using the same
// IP address into the same bucket and checks for equality
// using their summary to distinguish between endpoint measurements
// targeting the same IP address.
type CachingMeasurer struct {
	// cache is the underlying cache.
	cache *cachex.Cache

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
	cache *cachex.Cache, policy CachingPolicy) *CachingMeasurer {
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
	elist, _, _ := mx.readDNSLookupEntry(plan.Domain)
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		if !entry.M.CouldDeriveFrom(plan) {
			continue // this entry has been generated from another plan
		}
		if mx.policy.StaleDNSLookupMeasurement(&entry) {
			return nil, false
		}
		mx.logger.Infof("👛 DNS lookup entry '%s' in %v", plan.Summary(), time.Since(begin))
		return entry.M, true
	}
	return nil, false
}

func (mx *CachingMeasurer) storeDNSLookupMeasurement(dlm *DNSLookupMeasurement) error {
	elist, key, _ := mx.readDNSLookupEntry(dlm.Domain())
	var out []CachedDNSLookupMeasurement
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		if !entry.M.IsAnotherInstanceOf(dlm) {
			continue
		}
		out = append(out, entry)
	}
	out = append(out, CachedDNSLookupMeasurement{
		T: time.Now(),
		M: dlm,
	})
	return mx.writeDNSLookupEntry(key, out)
}

func (mx *CachingMeasurer) readDNSLookupEntry(
	summary string) ([]CachedDNSLookupMeasurement, cachex.ActionID, bool) {
	key, good := mx.summaryToActionID(summary)
	if !good {
		return nil, cachex.ActionID{}, false
	}
	data, err := mx.readEntry(key)
	if err != nil {
		return nil, key, false
	}
	var elist []CachedDNSLookupMeasurement
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, key, false
	}
	return elist, key, true
}

func (mx *CachingMeasurer) writeDNSLookupEntry(
	key cachex.ActionID, elist []CachedDNSLookupMeasurement) error {
	data, err := json.Marshal(elist)
	if err != nil {
		return err
	}
	return mx.writeEntry(key, data)
}

// canCacheEndpoint returns true if we can safely cache this endpoint plan or
// measurement. We can't currently cache endpoints using options that modify
// the measurement beyond what the summary captures. We will eventually remove
// this technical limitation. Until then, here's a safety net.
func canCacheEndpoint(opts *Options) bool {
	// TODO(bassosimone): extend Summary to take options into account.
	// Note: the following functions work as intended even if opts is nil.
	return opts.sni() == "" && len(opts.alpn()) <= 0 && opts.httpHostHeader() == ""
}

func (mx *CachingMeasurer) measureEndpoints(ctx context.Context,
	out chan<- *EndpointMeasurement, epnts ...*EndpointPlan) {
	// 0. synchronize with parent
	defer close(out)
	// 1. find the cached measurements and return them
	var todo []*EndpointPlan
	for _, plan := range epnts {
		if !canCacheEndpoint(plan.Options) {
			// Safety net against endpoints with weird options. See above.
			log.Printf("[BUG] cannot cache this endpoint: %+v", plan)
			continue
		}
		meas, found := mx.findEndpointMeasurement(plan)
		if !found {
			todo = append(todo, plan)
			continue
		}
		out <- meas
	}
	// 2. perform non-cached measurements and store them in cache
	for meas := range mx.measurer.MeasureEndpoints(ctx, todo...) {
		if !canCacheEndpoint(meas.Options) {
			// Safety net against endpoints with weird options. See above.
			log.Printf("[BUG] cannot cache this endpoint: %+v", meas)
		} else {
			_ = mx.storeEndpointMeasurement(meas)
		}
		out <- meas
	}
}

// CachedEndpointMeasurement is the cached form of an EndpointMeasurement.
type CachedEndpointMeasurement struct {
	T time.Time
	M *EndpointMeasurement
}

func (mx *CachingMeasurer) findEndpointMeasurement(
	plan *EndpointPlan) (*EndpointMeasurement, bool) {
	begin := time.Now()
	elist, _, _ := mx.readEndpointEntry(plan.IPAddress())
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		if !entry.M.CouldDeriveFrom(plan) {
			continue
		}
		if mx.policy.StaleEndpointMeasurement(&entry) {
			return nil, false
		}
		mx.logger.Infof("👛 endpoint entry '%s' in %v", entry.M.Summary(), time.Since(begin))
		return entry.M, true
	}
	return nil, false
}

func (mx *CachingMeasurer) storeEndpointMeasurement(em *EndpointMeasurement) error {
	elist, key, _ := mx.readEndpointEntry(em.IPAddress())
	var out []CachedEndpointMeasurement
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		if !em.IsAnotherInstanceOf(entry.M) {
			continue
		}
		out = append(out, entry)
	}
	out = append(out, CachedEndpointMeasurement{
		T: time.Now(),
		M: em,
	})
	return mx.writeEndpointEntry(key, out)
}

func (mx *CachingMeasurer) readEndpointEntry(
	summary string) ([]CachedEndpointMeasurement, cachex.ActionID, bool) {
	key, good := mx.summaryToActionID(summary)
	if !good {
		return nil, cachex.ActionID{}, false
	}
	data, err := mx.readEntry(key)
	if err != nil {
		return nil, key, false
	}
	var elist []CachedEndpointMeasurement
	if err := json.Unmarshal(data, &elist); err != nil {
		return nil, key, false
	}
	return elist, key, true
}

func (mx *CachingMeasurer) writeEndpointEntry(
	key cachex.ActionID, elist []CachedEndpointMeasurement) error {
	data, err := json.Marshal(elist)
	if err != nil {
		return err
	}
	return mx.writeEntry(key, data)
}

func (mx *CachingMeasurer) writeEntry(actionID cachex.ActionID, data []byte) error {
	return mx.cache.PutBytes(actionID, data)
}

func (mx *CachingMeasurer) readEntry(actionID cachex.ActionID) ([]byte, error) {
	data, _, err := mx.cache.GetBytes(actionID)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (mx *CachingMeasurer) summaryToActionID(summary string) (cachex.ActionID, bool) {
	h := cachex.NewHash("keyHash")
	if _, err := h.Write([]byte(summary)); err != nil {
		return cachex.ActionID{}, false
	}
	return h.Sum(), true
}
