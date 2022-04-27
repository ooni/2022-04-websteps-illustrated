package baseline

//
// Contains a server/TH for the baseline experiment.
//

import (
	"net"
	"net/http"

	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
	"github.com/miekg/dns"
)

// Server is the baseline server.
type Server struct {
	// certfile contains the MANDATORY cert file.
	certfile string

	// keyfile contains the MANDATORY key file.
	keyfile string
}

// NewServer creates a new server instance.
func NewServer(certfile, keyfile string) *Server {
	return &Server{
		certfile: certfile,
		keyfile:  keyfile,
	}
}

// Listen starts listening. This operation requires root privileges
// on most Unix systems except macOS. You SHOULD drop privileges once
// you've called this operation and before calling Listener.Start.
func (s *Server) Listen() (*Listener, error) {
	dns, err := net.ListenPacket("udp", ":53")
	if err != nil {
		return nil, err
	}
	https, err := net.Listen("tcp", ":443")
	if err != nil {
		dns.Close()
		return nil, err
	}
	http, err := net.Listen("tcp", ":80")
	if err != nil {
		https.Close()
		dns.Close()
		return nil, err
	}
	listener := &Listener{
		certfile: s.certfile,
		keyfile:  s.keyfile,
		dns:      dns,
		https:    https,
		http:     http,
	}
	return listener, nil
}

// Listener is the listener for the DNS, HTTP, HTTPS baseline server.
type Listener struct {
	// certfile contains the certificate file.
	certfile string

	// keyfile contains the key file.
	keyfile string

	// dns is the DNS listener.
	dns net.PacketConn

	// https is the HTTPS listener.
	https net.Listener

	// http is the HTTP listener.
	http net.Listener
}

// Start starts the baseline test helper using this listener.
func (li *Listener) Start() {
	ds := &dns.Server{
		Handler:    &dnsHandler{},
		Net:        "udp",
		PacketConn: li.dns,
	}
	go func() {
		err := ds.ActivateAndServe()
		runtimex.PanicOnError(err, "ActivateAndServe failed")
	}()
	go func() {
		err := http.Serve(li.http, &httpHandler{})
		runtimex.PanicOnError(err, "http.Serve failed")
	}()
	go func() {
		err := http.ServeTLS(li.https, &httpHandler{}, li.certfile, li.keyfile)
		runtimex.PanicOnError(err, "http.ServeTLS failed")
	}()
}

// dnsHandler handles DNS requests.
type dnsHandler struct{}

// ServeDNS serves a DNS request
func (h *dnsHandler) ServeDNS(rw dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) < 1 {
		rw.WriteMsg(h.failure(req))
		return
	}
	rw.WriteMsg(h.okay(req))
}

// failure returns a message containing the ServerFailure code.
func (h *dnsHandler) failure(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.Compress = true
	m.MsgHdr.RecursionAvailable = true
	m.SetRcode(req, dns.RcodeServerFailure)
	return m
}

// okay returns a message containing an OK response.
func (h *dnsHandler) okay(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.Compress = true
	m.MsgHdr.RecursionAvailable = true
	m.SetReply(req)
	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.ParseIP(defaultIPv4Addr),
		})
	}
	return m
}

// httpHandler is the HTTP handler.
type httpHandler struct{}

// ServeHTTP serves an HTTP request.
func (h *httpHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Write(defaultWebpage)
}
