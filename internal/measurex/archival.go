package measurex

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

//
// Archival
//
// Convert to the archival data format.
//

// ArchivalDNSLookupMeasurement is an archival DNS lookup measurement.
type ArchivalDNSLookupMeasurement struct {
	// ID is the unique ID of this measurement.
	ID int64 `json:"id,omitempty"`

	// Domain is the domain this lookup refers to.
	Domain string `json:"domain"`

	// Failure is the failure that occurred.
	Failure *string `json:"failure"`

	// Queries contains the DNS lookup events.
	Queries []model.ArchivalDNSLookupResult `json:"queries"`
}

// ToArchival converts a DNSLookupMeasurement to ArchivalDNSLookupMeasurement.
func (m *DNSLookupMeasurement) ToArchival(begin time.Time) ArchivalDNSLookupMeasurement {
	return ArchivalDNSLookupMeasurement{
		ID:      m.ID,
		Domain:  m.Domain(),
		Failure: m.Failure().ToArchivalFailure(),
		Queries: m.queries(begin),
	}
}

// queries is an helper function to construct an ArchivalDNSLookupMeasurement.
func (m *DNSLookupMeasurement) queries(begin time.Time) (out []model.ArchivalDNSLookupResult) {
	for _, rt := range m.RoundTrip {
		out = append(out, *rt.ToArchival(begin))
	}
	return
}

// ArchivalEndpointMeasurement is the archival format of an endpoint measurement.
type ArchivalEndpointMeasurement struct {
	// ID is the unique ID of this measurement.
	ID int64 `json:"id,omitempty"`

	// URL is the URL we're fetching.
	URL string `json:"url"`

	// Endpoint is the endpoint network.
	Network string `json:"network"`

	// Address is the endpoint address.
	Address string `json:"address"`

	// Failure is the error that occurred.
	Failure *string `json:"failure"`

	// FailedOperation is the operation that failed.
	FailedOperation *string `json:"failed_operation"`

	// NetworkEvent contains network events (if any).
	NetworkEvents []model.ArchivalNetworkEvent `json:"network_events"`

	// TCPConnect contains the TCP connect event (if any).
	TCPConnect *model.ArchivalTCPConnectResult `json:"tcp_connect"`

	// QUICTLSHandshake contains the QUIC/TLS handshake event (if any).
	QUICTLSHandshake *model.ArchivalTLSOrQUICHandshakeResult `json:"quic_tls_handshake"`

	// HTTPRoundTrip contains the HTTP round trip event (if any).
	HTTPRoundTrip *model.ArchivalHTTPRequestResult `json:"request"`
}

// ToArchival converts a EndpointMeasurement to ArchivalEndpointMeasurement.
func (m *EndpointMeasurement) ToArchival(
	begin time.Time, bodyFlags int64) ArchivalEndpointMeasurement {
	return ArchivalEndpointMeasurement{
		ID:               m.ID,
		URL:              m.URL.String(),
		Network:          string(m.Network),
		Address:          m.Address,
		Failure:          m.Failure.ToArchivalFailure(),
		FailedOperation:  m.FailedOperation.ToArchivalFailure(),
		NetworkEvents:    archival.NewArchivalNetworkEventList(begin, m.NetworkEvent),
		TCPConnect:       m.toArchivalTCPConnectResult(begin),
		QUICTLSHandshake: m.toArchivalTLSOrQUICHandshakeResult(begin),
		HTTPRoundTrip:    m.toArchivalHTTPRequestResult(begin, bodyFlags),
	}
}

func (m *EndpointMeasurement) toArchivalTCPConnectResult(begin time.Time) (out *model.ArchivalTCPConnectResult) {
	if m.TCPConnect != nil {
		v := m.TCPConnect.ToArchivalTCPConnectResult(begin)
		out = &v
	}
	return
}

func (m *EndpointMeasurement) toArchivalTLSOrQUICHandshakeResult(
	begin time.Time) (out *model.ArchivalTLSOrQUICHandshakeResult) {
	if m.QUICTLSHandshake != nil {
		v := m.QUICTLSHandshake.ToArchival(begin)
		out = &v
	}
	return
}

func (m *EndpointMeasurement) toArchivalHTTPRequestResult(
	begin time.Time, flags int64) (out *model.ArchivalHTTPRequestResult) {
	if m.HTTPRoundTrip != nil {
		v := m.HTTPRoundTrip.ToArchival(begin, flags)
		out = &v
	}
	return
}

// ArchivalURLMeasurement is the archival format of an URL measurement.
type ArchivalURLMeasurement struct {
	// ID is the unique ID of this URLMeasurement.
	ID int64 `json:"id"`

	// EndpointIDs contains the ID of the EndpointMeasurement(s) that
	// generated this URLMeasurement through redirects.
	EndpointIDs []int64 `json:"endpoint_ids"`

	// URL is the underlying URL to measure.
	URL string `json:"url"`

	// Cookies contains the cookies.
	Cookies []string `json:"cookies"`

	// DNS contains a list of DNS measurements.
	DNS []ArchivalDNSLookupMeasurement `json:"dns"`

	// Endpoint contains a list of endpoint measurements.
	Endpoint []ArchivalEndpointMeasurement `json:"endpoint"`
}

// ToArchival converts URLMeasurement to ArchivalURLMeasurement.
func (m *URLMeasurement) ToArchival(begin time.Time, bodyFlags int64) ArchivalURLMeasurement {
	return ArchivalURLMeasurement{
		ID:          m.ID,
		EndpointIDs: m.EndpointIDs,
		URL:         m.URL.String(),
		Cookies:     m.toArchivalCookies(),
		DNS:         NewArchivalDNSLookupMeasurementList(begin, m.DNS),
		Endpoint: NewArchivalEndpointMeasurementList(
			begin, m.Endpoint, bodyFlags),
	}
}

func (m *URLMeasurement) toArchivalCookies() (out []string) {
	for _, cookie := range m.Cookies {
		out = append(out, cookie.String())
	}
	return
}

// NewArchivalDNSLookupMeasurementList converts a []*DNSLookupMeasurement into
// a []ArchivalDNSLookupMeasurement.
func NewArchivalDNSLookupMeasurementList(
	begin time.Time, in []*DNSLookupMeasurement) (out []ArchivalDNSLookupMeasurement) {
	for _, entry := range in {
		out = append(out, entry.ToArchival(begin))
	}
	return
}

// NewArchivalEndpointMeasurementList converts a []*EndpointMeasurement into
// a []ArchivalEndpointMeasurement.
func NewArchivalEndpointMeasurementList(begin time.Time,
	in []*EndpointMeasurement, bodyFlags int64) (out []ArchivalEndpointMeasurement) {
	for _, entry := range in {
		out = append(out, entry.ToArchival(begin, bodyFlags))
	}
	return
}
