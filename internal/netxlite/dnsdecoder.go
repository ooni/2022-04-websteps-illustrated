package netxlite

import (
	"errors"
	"net"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/miekg/dns"
)

// DNSDecoderMiekg uses github.com/miekg/dns to implement the Decoder.
type DNSDecoderMiekg struct{}

var (
	// ErrDNSReplyWithWrongQueryID indicates we have got a DNS reply with the wrong queryID.
	ErrDNSReplyWithWrongQueryID = errors.New(FailureDNSReplyWithWrongQueryID)

	// ErrDNSIsResponse indicates that we were passed a DNS response.
	ErrDNSIsResponse = errors.New("ooresolver: expected query but received response")

	// ErrDNSIsQuery indicates that we were passed a DNS query.
	ErrDNSIsQuery = errors.New("ooresolver: expected response but received query")
)

func (d *DNSDecoderMiekg) ParseQuery(data []byte) (*dns.Msg, error) {
	query := &dns.Msg{}
	if err := query.Unpack(data); err != nil {
		return nil, err
	}
	if query.Response {
		return nil, ErrDNSIsResponse
	}
	return query, nil
}

func (d *DNSDecoderMiekg) ParseReply(data []byte) (*dns.Msg, error) {
	reply := &dns.Msg{}
	if err := reply.Unpack(data); err != nil {
		return nil, err
	}
	if !reply.Response {
		return nil, ErrDNSIsQuery
	}
	return reply, nil
}

func (d *DNSDecoderMiekg) ParseReplyForQueryID(data []byte, queryID uint16) (*dns.Msg, error) {
	reply, err := d.ParseReply(data)
	if err != nil {
		return nil, err
	}
	if reply.Id != queryID {
		return nil, ErrDNSReplyWithWrongQueryID
	}
	return reply, nil
}

func (d *DNSDecoderMiekg) rcodeToError(reply *dns.Msg) error {
	// TODO(bassosimone): map more errors to net.DNSError names
	// TODO(bassosimone): add support for lame referral.
	switch reply.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeNameError:
		return ErrOODNSNoSuchHost
	case dns.RcodeRefused:
		return ErrOODNSRefused
	case dns.RcodeServerFailure:
		return ErrOODNSServfail
	default:
		return ErrOODNSMisbehaving
	}
}

func (d *DNSDecoderMiekg) DecodeLookupHTTPS(data []byte, queryID uint16) (*model.HTTPSSvc, error) {
	reply, err := d.ParseReplyForQueryID(data, queryID)
	if err != nil {
		return nil, err
	}
	return d.DecodeReplyLookupHTTPS(reply)
}

func (d *DNSDecoderMiekg) DecodeLookupNS(data []byte, queryID uint16) ([]*net.NS, error) {
	reply, err := d.ParseReplyForQueryID(data, queryID)
	if err != nil {
		return nil, err
	}
	return d.DecodeReplyLookupNS(reply)
}

func (d *DNSDecoderMiekg) DecodeReplyLookupHTTPS(reply *dns.Msg) (*model.HTTPSSvc, error) {
	if err := d.rcodeToError(reply); err != nil {
		return nil, err
	}
	out := &model.HTTPSSvc{}
	for _, answer := range reply.Answer {
		switch avalue := answer.(type) {
		case *dns.HTTPS:
			for _, v := range avalue.Value {
				switch extv := v.(type) {
				case *dns.SVCBAlpn:
					out.ALPN = extv.Alpn
				case *dns.SVCBIPv4Hint:
					for _, ip := range extv.Hint {
						out.IPv4 = append(out.IPv4, ip.String())
					}
				case *dns.SVCBIPv6Hint:
					for _, ip := range extv.Hint {
						out.IPv6 = append(out.IPv6, ip.String())
					}
				}
			}
		}
	}
	if len(out.IPv4) <= 0 && len(out.IPv6) <= 0 {
		return nil, ErrOODNSNoAnswer
	}
	if len(out.ALPN) <= 0 {
		out.ALPN = []string{} // ensure it's not nil
	}
	if len(out.IPv4) <= 0 {
		out.IPv4 = []string{} // ensure it's not nil
	}
	if len(out.IPv6) <= 0 {
		out.IPv6 = []string{} // ensure it's not nil
	}
	return out, nil
}

func (d *DNSDecoderMiekg) DecodeReplyLookupNS(reply *dns.Msg) ([]*net.NS, error) {
	if err := d.rcodeToError(reply); err != nil {
		return nil, err
	}
	out := []*net.NS{}
	for _, answer := range reply.Answer {
		switch avalue := answer.(type) {
		case *dns.NS:
			out = append(out, &net.NS{Host: avalue.Ns})
		}
	}
	if len(out) < 1 {
		return nil, ErrOODNSNoAnswer
	}
	return out, nil
}

func (d *DNSDecoderMiekg) DecodeLookupHost(
	qtype uint16, data []byte, queryID uint16) ([]string, error) {
	reply, err := d.ParseReplyForQueryID(data, queryID)
	if err != nil {
		return nil, err
	}
	return d.DecodeReplyLookupHost(qtype, reply)
}

func (d *DNSDecoderMiekg) DecodeReplyLookupHost(qtype uint16, reply *dns.Msg) ([]string, error) {
	if err := d.rcodeToError(reply); err != nil {
		return nil, err
	}
	var addrs []string
	for _, answer := range reply.Answer {
		switch v := answer.(type) {
		case *dns.A:
			if qtype == dns.TypeA || qtype == dns.TypeANY {
				addrs = append(addrs, v.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
				addrs = append(addrs, v.AAAA.String())
			}
		}
	}
	if len(addrs) <= 0 {
		return nil, ErrOODNSNoAnswer
	}
	return addrs, nil
}

var _ model.DNSDecoder = &DNSDecoderMiekg{}
