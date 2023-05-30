package dnsping

//
// URLAddress
//
// Converts result to URLAddressList
//

import (
	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/archival"
	"github.com/ooni/2022-04-websteps-illustrated/internal/measurex"
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
		dns = append(dns, spr.DNSLookupMeasurementList(urlMeasurementID, domain)...)
	}
	endpoint := []*measurex.EndpointMeasurement{}
	return measurex.NewURLAddressList(urlMeasurementID, domain, dns, endpoint)
}

// DNSLookupMeasurementList converts a SinglePingResult into a
// list containing DNSLookupMeasurement instances.
func (spr *SinglePingResult) DNSLookupMeasurementList(
	urlMeasurementID int64, domain string) (out []*measurex.DNSLookupMeasurement) {
	if domain != spr.Domain {
		// Ensure that we only include the domain we're interested into
		return
	}
	for _, entry := range spr.Replies {
		if entry.Error != "" {
			continue // ensure we skip any ping attempt that failed
		}
		// TODO(bassosimone): here we could probably use a factory
		out = append(out, &measurex.DNSLookupMeasurement{
			ID:               entry.ID,
			URLMeasurementID: urlMeasurementID,
			ReverseAddress:   "",
			Lookup: &archival.FlatDNSLookupEvent{
				ALPNs:           entry.ALPNs,
				Addresses:       entry.Addresses,
				CNAME:           "",
				Domain:          spr.Domain,
				Failure:         entry.Error,
				Finished:        entry.Finished,
				LookupType:      spr.lookupType(),
				NS:              []string{},
				ResolverAddress: "dnsping",
				ResolverNetwork: "",
				Started:         spr.Started,
			},
			RoundTrip: []*archival.FlatDNSRoundTripEvent{},
		})
	}
	return
}

func (spr *SinglePingResult) lookupType() archival.DNSLookupType {
	switch spr.QueryType {
	case dns.TypeA, dns.TypeAAAA:
		return archival.DNSLookupTypeGetaddrinfo
	case dns.TypeHTTPS:
		return archival.DNSLookupTypeHTTPS
	default:
		return ""
	}
}
