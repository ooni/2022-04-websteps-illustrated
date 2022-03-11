package dnsping

//
// URLAddress
//
// Converts result to URLAddressList
//

import (
	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// URLAddressList converts Result to []*URLAddress.
//
// Arguments:
//
// - urlMeasurementID is the URLMeasurement in which context we're working
//
// - domain is the domain to filter dnsping results for
//
// Because dnsping may test several domains in parallel, we need
// to be sure we only include the one we care about.
func (r *Result) URLAddressList(
	urlMeasurementID int64, domain string) ([]*measurex.URLAddress, bool) {
	dns := []*measurex.DNSLookupMeasurement{}
	for _, spr := range r.Pings {
		dns = append(dns, spr.dnsLookupMeasurementList(urlMeasurementID, domain)...)
	}
	endpoint := []*measurex.EndpointMeasurement{}
	return measurex.NewURLAddressList(urlMeasurementID, dns, endpoint)
}

// dnsLookupMeasurementList converts a SinglePingResult into a
// list containing DNSLookupMeasurement instances.
func (spr *SinglePingResult) dnsLookupMeasurementList(
	urlMeasurementID int64, domain string) (out []*measurex.DNSLookupMeasurement) {
	if domain != spr.Domain {
		// Ensure that we only include the domain we're interested into
		return
	}
	for _, entry := range spr.Replies {
		out = append(out, &measurex.DNSLookupMeasurement{
			ID:               entry.ID,
			URLMeasurementID: urlMeasurementID,
			Lookup: &archival.FlatDNSLookupEvent{
				// Because we may be including ALPNs/IPv4/IPv6 it's more
				// proper to fake out an HTTPS lookup than A or AAAA.
				ALPNs:           entry.ALPNs,
				Addresses:       entry.Addresses,
				Domain:          spr.Domain,
				Failure:         entry.Error,
				Finished:        entry.Finished,
				LookupType:      archival.DNSLookupTypeHTTPS,
				ResolverAddress: "dnsping",
				ResolverNetwork: "",
				Started:         spr.Started,
			},
			RoundTrip: []*archival.FlatDNSRoundTripEvent{},
		})
	}
	return
}
