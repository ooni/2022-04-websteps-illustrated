package netxlite

import (
	"net"

	"github.com/miekg/dns"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
)

// DNSEncoderMiekg uses github.com/miekg/dns to implement the Encoder.
type DNSEncoderMiekg struct{}

const (
	// dnsPaddingDesiredBlockSize is the size that the padded query should be multiple of
	dnsPaddingDesiredBlockSize = 128

	// dnsEDNS0MaxResponseSize is the maximum response size for EDNS0
	dnsEDNS0MaxResponseSize = 4096

	// dnsDNSSECEnabled turns on support for DNSSEC when using EDNS0
	dnsDNSSECEnabled = true
)

func (e *DNSEncoderMiekg) EncodeQuery(
	domain string, qtype uint16, padding bool) ([]byte, uint16, error) {
	question := dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = true
	query.Question = make([]dns.Question, 1)
	query.Question[0] = question
	if padding {
		query.SetEdns0(dnsEDNS0MaxResponseSize, dnsDNSSECEnabled)
		// Clients SHOULD pad queries to the closest multiple of
		// 128 octets RFC8467#section-4.1. We inflate the query
		// length by the size of the option (i.e. 4 octets). The
		// cast to uint is necessary to make the modulus operation
		// work as intended when the desiredBlockSize is smaller
		// than (query.Len()+4) ¯\_(ツ)_/¯.
		remainder := (dnsPaddingDesiredBlockSize - uint(query.Len()+4)) % dnsPaddingDesiredBlockSize
		opt := new(dns.EDNS0_PADDING)
		opt.Padding = make([]byte, remainder)
		query.IsEdns0().Option = append(query.IsEdns0().Option, opt)
	}
	data, err := query.Pack()
	if err != nil {
		return nil, 0, err
	}
	return data, query.Id, nil
}

func (e *DNSEncoderMiekg) EncodeReply(query *dns.Msg, addresses []string) (*dns.Msg, error) {
	if len(query.Question) != 1 {
		return nil, errDNSExpectedSingleQuestion
	}
	m := new(dns.Msg)
	m.Compress = true
	m.MsgHdr.RecursionAvailable = true
	m.SetReply(query)
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		switch isIPv6(addr) {
		case false:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   query.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: ip,
			})
		case true:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   query.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				AAAA: ip,
			})

		}
	}
	return m, nil
}

var _ model.DNSEncoder = &DNSEncoderMiekg{}
