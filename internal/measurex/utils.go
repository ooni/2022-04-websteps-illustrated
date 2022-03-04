package measurex

//
// Utils
//
// This is where we put free functions.
//

import (
	"errors"
	"net/url"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
)

// ALPNForHTTPEndpoint selects the correct ALPN for an HTTP endpoint
// given the network. On failure, we return an empty list.
func ALPNForHTTPEndpoint(network archival.NetworkType) []string {
	switch network {
	case archival.NetworkTypeQUIC:
		return []string{"h3"}
	case archival.NetworkTypeTCP:
		return []string{"h2", "http/1.1"}
	default:
		return []string{}
	}
}

// ErrCannotDeterminePortFromURL indicates that we could not determine
// the correct port from the URL authority and scheme.
var ErrCannotDeterminePortFromURL = errors.New("cannot determine port from URL")

// PortFromURL returns the port determined from the URL or an error.
func PortFromURL(URL *url.URL) (string, error) {
	switch {
	case URL.Port() != "":
		return URL.Port(), nil
	case URL.Scheme == "https":
		return "443", nil
	case URL.Scheme == "http":
		return "80", nil
	default:
		return "", ErrCannotDeterminePortFromURL
	}
}
