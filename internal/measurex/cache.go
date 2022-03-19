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
	"errors"
	"log"
	"strings"
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
// 1. it caches DNSLookupMeasurement based on the domain
// and the resolver's network and address.
//
// 2. it caches EndpointMeasurement based on the endpoint summary.
//
// In case some endpoints or DNS lookups cannot be cached, this
// code will emit warning messages. (Caching is a complex business
// and the current code does not attempt to cache endpoints that
// use options such as the SNI or the Host header.)
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
		var resolvers []*DNSResolverInfo
		for _, reso := range plan.Resolvers {
			meas, found := mx.findDNSLookupMeasurement(plan, reso)
			if !found {
				resolvers = append(resolvers, reso)
				continue
			}
			out <- meas
		}
		if len(resolvers) <= 0 {
			continue
		}
		copy := plan.Clone()
		copy.Resolvers = resolvers
		todo = append(todo, copy)
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

func (mx *CachingMeasurer) dnsPlanCacheKey(dlp *DNSLookupPlan, reso *DNSResolverInfo) string {
	return strings.Join([]string{dlp.Domain(), string(reso.Network), reso.Address}, " ")
}

func (mx *CachingMeasurer) dnsMeasurementCacheKey(m *DNSLookupMeasurement) string {
	return strings.Join([]string{m.Domain(), string(m.ResolverNetwork()), m.ResolverAddress()}, " ")
}

func (mx *CachingMeasurer) findDNSLookupMeasurement(plan *DNSLookupPlan, reso *DNSResolverInfo) (
	*DNSLookupMeasurement, bool) {
	pk := mx.dnsPlanCacheKey(plan, reso)
	elist, _, _ := mx.readDNSLookupEntry(pk)
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		ek := mx.dnsMeasurementCacheKey(entry.M)
		if pk != ek {
			continue
		}
		if mx.policy.StaleDNSLookupMeasurement(&entry) {
			return nil, false
		}
		mx.logger.Infof("👛 DNS lookup entry '%s'", pk)
		return entry.M, true
	}
	return nil, false
}

func (mx *CachingMeasurer) storeDNSLookupMeasurement(dlm *DNSLookupMeasurement) error {
	dk := mx.dnsMeasurementCacheKey(dlm)
	elist, key, _ := mx.readDNSLookupEntry(dk)
	var out []CachedDNSLookupMeasurement
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		ek := mx.dnsMeasurementCacheKey(entry.M)
		if dk == ek {
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
	summary, good := plan.Summary()
	if !good {
		return nil, false
	}
	elist, _, _ := mx.readEndpointEntry(summary)
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		realSummary, good := entry.M.Summary()
		if !good || realSummary != summary {
			continue
		}
		if mx.policy.StaleEndpointMeasurement(&entry) {
			return nil, false
		}
		mx.logger.Infof("👛 endpoint entry '%s'", summary)
		return entry.M, true
	}
	return nil, false
}

func (mx *CachingMeasurer) storeEndpointMeasurement(em *EndpointMeasurement) error {
	summary, good := em.Summary()
	if !good {
		return errors.New("cannot compute summary")
	}
	elist, key, _ := mx.readEndpointEntry(summary)
	var out []CachedEndpointMeasurement
	for _, entry := range elist {
		if entry.M == nil {
			continue
		}
		realSummary, good := entry.M.Summary()
		if !good || realSummary == summary {
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
