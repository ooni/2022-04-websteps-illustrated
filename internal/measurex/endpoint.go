package measurex

//
// Endpoint
//
// This file contains the definition of Endpoint and HTTPEndpoint
//

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
)

// EndpointNetwork is the network of an endpoint.
type EndpointNetwork string

const (
	// NetworkTCP identifies endpoints using TCP.
	NetworkTCP = EndpointNetwork("tcp")

	// NetworkQUIC identifies endpoints using QUIC.
	NetworkQUIC = EndpointNetwork("quic")
)

// Endpoint is an endpoint for a domain.
type Endpoint struct {
	// Network is the network (e.g., "tcp", "quic")
	Network EndpointNetwork

	// Address is the endpoint address (e.g., "8.8.8.8:443")
	Address string
}

// String converts an endpoint to a string (e.g., "8.8.8.8:443/tcp")
func (e *Endpoint) String() string {
	return fmt.Sprintf("%s/%s", e.Address, e.Network)
}

// HTTPEndpoint is an HTTP/HTTPS/HTTP3 endpoint.
type HTTPEndpoint struct {
	// Domain is the endpoint domain (e.g., "dns.google").
	Domain string

	// Network is the network (e.g., "tcp" or "quic").
	Network EndpointNetwork

	// Address is the endpoint address (e.g., "8.8.8.8:443").
	Address string

	// SNI is the SNI to use (only used with URL.scheme == "https").
	SNI string

	// ALPN is the ALPN to use (only used with URL.scheme == "https").
	ALPN []string

	// URL is the endpoint URL.
	URL *url.URL

	// Header contains request headers.
	Header http.Header
}

// String converts an HTTP endpoint to a string (e.g., "8.8.8.8:443/tcp")
func (e *HTTPEndpoint) String() string {
	return fmt.Sprintf("%s/%s", e.Address, e.Network)
}

// EndpointMeasurement is an endpoint measurement.
type EndpointMeasurement struct {
	// Network is the network of this endpoint.
	Network EndpointNetwork

	// Address is the address of this endpoint.
	Address string

	// ID is the unique ID of this measurement.
	ID int64

	// An EndpointMeasurement contains a Trace.
	*archival.Trace
}

func (mx *Measurer) newEndpointMeasurement(
	network EndpointNetwork, address string, trace *archival.Trace) *EndpointMeasurement {
	return &EndpointMeasurement{
		Network: NetworkTCP,
		Address: address,
		ID:      mx.IDGenerator.Add(1),
		Trace:   trace,
	}
}

// HTTPEndpointMeasurement is an HTTP endpoint measurement.
type HTTPEndpointMeasurement struct {
	// URL is the URL this measurement refers to.
	URL string

	// Network is the network of this endpoint.
	Network EndpointNetwork

	// Address is the address of this endpoint.
	Address string

	// ID is the unique ID of this measurement.
	ID int64

	// An HTTPEndpointMeasurement contains a Trace.
	*archival.Trace
}

func (mx *Measurer) newHTTPEndpointMeasurement(URL string, network EndpointNetwork,
	address string, trace *archival.Trace) *HTTPEndpointMeasurement {
	return &HTTPEndpointMeasurement{
		URL:     URL,
		Network: NetworkTCP,
		Address: address,
		ID:      mx.IDGenerator.Add(1),
		Trace:   trace,
	}
}
