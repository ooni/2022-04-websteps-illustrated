package websteps

//
// DNSPing
//
// Integration with DNSPing as a follow-up experiment.
//

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/archival"
	"github.com/ooni/2022-04-websteps-illustrated/internal/dnsping"
	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/measurex"
	"github.com/ooni/2022-04-websteps-illustrated/internal/netxlite"
)

// dnsPingFollowUp runs the dnsping sub-experiment as a follow-up. We will
// actually only run dnsping for UDP resolvers in these cases:
//
// 1. we see a reply with DNS bogons (in which case we hope that dnsping
// allows us to detect legit late replies, if any);
//
// 2. we see a timeout (in which case we hope that dnsping allows us
// to retry the query a bunch of times);
//
// 3. we see NXDOMAIN (in which case we also hope that dnsping allows us
// to detect possible legit late or duplicate DNS responses).
//
// When we start a background dnsping, we return a valid channel
// and true. Otherwise we return a nil channel and false.
//
// The dnsping will run in parallel with other websteps operation and
// you'll be able to obtain the result from the returned channel.
//
// The pointer returned by the channel is nil if there's no work that the
// dnsping experiment has actually performed. This happens when none of
// three above triggering conditions are actually met.
func (c *Client) dnsPingFollowUp(ctx context.Context, mx measurex.AbstractMeasurer,
	current *measurex.URLMeasurement) (<-chan *dnsping.Result, bool) {
	var overall []*dnsping.SinglePingPlan
	for _, entry := range c.dnsPingSelectQueries(current.DNS) {
		plans := c.dnsPingMakePlan(entry)
		overall = append(overall, plans...)
	}
	if len(overall) <= 0 {
		return nil, false
	}
	// The dnsping codebase does not emit this information but it's useful
	// when reading the logs to know it has started.
	logcat.Substep("starting dnsping in the background...")
	engine := c.NewDNSPingEngine(mx, mx.FlattenOptions().DNSLookupTimeout)
	return engine.RunAsync(overall), true
}

// dnsPingSelectQueries filters the list of all the queries
// we have performed so far and chooses which ones to test.
//
// The criteria for selecting which entries to keep is
// explained in dnsPingFollowUp's docs.
//
// Note: the returned list contains pointers to queries in the original
// list, so it's not data-race-safe to modify any element.
func (c *Client) dnsPingSelectQueries(in []*measurex.DNSLookupMeasurement) (
	out []*measurex.DNSLookupMeasurement) {
	for _, entry := range in {
		if entry.ResolverNetwork() != archival.NetworkTypeUDP {
			continue // we can only retry UDP
		}
		if entry.ResolverAddress() == "" {
			logcat.Bugf("UDP query w/o resolver address")
			continue // should not happen but #safetyNet
		}
		switch v := entry.Failure(); v {
		case netxlite.FailureGenericTimeoutError,
			netxlite.FailureDNSNXDOMAINError:
			logcat.Noticef("query #%d failed with %s; I will investigate using dnsping", entry.ID, v)
			out = append(out, entry)
		case "":
			for _, addr := range entry.Addresses() {
				if netxlite.IsBogon(addr) {
					logcat.Noticef("query #%d contains bogons; I will investigate using dnsping", entry.ID)
					out = append(out, entry)
					break // one bogon is enough to warrant a retry
				}
			}
		}
	}
	return
}

// dnsPingMakePlan returns a plan for retesting this query using dnsping.
//
// The general idea of the algorithm is that we cannot run a long
// evenly spaced ping, so we'll send increasingly spaced packets in
// a relatively short time frame. The total runtime of this plan
// would be the sum of the QueryTimeout and of the last delay.
func (c *Client) dnsPingMakePlan(
	dlm *measurex.DNSLookupMeasurement) (out []*dnsping.SinglePingPlan) {
	// Implementation note: delays are absolute with respect to the
	// moment in which we start running dnsping. Because we're testing
	// a bunch of queries in parallel, some packets are going to
	// be emitted ~at the same time. Still, it shouldn't be much traffic.
	delays := []time.Duration{
		0 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
	}
	for _, delay := range delays {
		switch dlm.LookupType() {
		case archival.DNSLookupTypeGetaddrinfo:
			// If we're redoing a getaddrinfo type lookup, we need to
			// query for both A and AAAA at the same time
			out = append(out, &dnsping.SinglePingPlan{
				ResolverAddress: dlm.ResolverAddress(),
				Delay:           delay,
				Domain:          dlm.Domain(),
				QueryType:       dns.TypeA,
			})
			out = append(out, &dnsping.SinglePingPlan{
				ResolverAddress: dlm.ResolverAddress(),
				Delay:           delay,
				Domain:          dlm.Domain(),
				QueryType:       dns.TypeAAAA,
			})
		case archival.DNSLookupTypeHTTPS:
			out = append(out, &dnsping.SinglePingPlan{
				ResolverAddress: dlm.ResolverAddress(),
				Delay:           delay,
				Domain:          dlm.Domain(),
				QueryType:       dns.TypeHTTPS,
			})
		default:
			// nothing
		}
	}
	return
}
