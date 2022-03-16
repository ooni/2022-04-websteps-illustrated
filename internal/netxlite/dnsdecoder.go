package netxlite

import (
	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/miekg/dns"
)

// DNSDecoderMiekg uses github.com/miekg/dns to implement the Decoder.
type DNSDecoderMiekg struct{}

func (d *DNSDecoderMiekg) ParseReply(data []byte) (*dns.Msg, error) {
	reply := &dns.Msg{}
	if err := reply.Unpack(data); err != nil {
		return nil, err
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
	default:
		return ErrOODNSMisbehaving
	}
}

func (d *DNSDecoderMiekg) DecodeHTTPS(data []byte) (*model.HTTPSSvc, error) {
	reply, err := d.ParseReply(data)
	if err != nil {
		return nil, err
	}
	return d.DecodeReplyLookupHTTPS(reply)
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

func (d *DNSDecoderMiekg) DecodeLookupHost(qtype uint16, data []byte) ([]string, error) {
	reply, err := d.ParseReply(data)
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
		switch qtype {
		case dns.TypeA:
			if rra, ok := answer.(*dns.A); ok {
				ip := rra.A
				addrs = append(addrs, ip.String())
			}
		case dns.TypeAAAA:
			if rra, ok := answer.(*dns.AAAA); ok {
				ip := rra.AAAA
				addrs = append(addrs, ip.String())
			}
		}
	}
	if len(addrs) <= 0 {
		return nil, ErrOODNSNoAnswer
	}
	return addrs, nil
}

var _ model.DNSDecoder = &DNSDecoderMiekg{}
