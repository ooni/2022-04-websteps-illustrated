package measurex

//
// Utils
//
// This is where we put free functions.
//

import (
	"errors"
	"net/http"
	"net/url"
	"sort"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
)

// ALPNForHTTPSEndpoint selects the correct ALPN for an HTTP endpoint
// given the network. On failure, we return an empty list.
func ALPNForHTTPSEndpoint(network archival.NetworkType) []string {
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

// SerializeCookies takes in input []*http.Cookie and returns
// a []string where each string is a serialized cookie.
func SerializeCookies(in []*http.Cookie) (out []string) {
	for _, cookie := range in {
		out = append(out, cookie.String())
	}
	return
}

// SortedSerializedCookies returns a sorted copy of the cookies.
func SortedSerializedCookies(in []*http.Cookie) (out []string) {
	out = SerializeCookies(in)
	sort.Strings(out)
	return
}

// CanonicalURLString returns a representation of the given URL that should be
// more canonical than the random URLs returned by web services.
//
// We need as canonical as possible URLs in URLRedirectDeque because
// their string representation is used to decide whether we need to
// follow redirects or not.
//
// SPDX-License-Identifier: MIT
//
// Adapted from: https://github.com/sekimura/go-normalize-url.
func CanonicalURLString(URL *url.URL) string {
	u := newURLWithScheme(URL, URL.Scheme)
	// TODO(bassosimone): canonicalize path if needed?
	// TODO(bassosimone): how about IDNA?
	v := u.Query()
	u.RawQuery = v.Encode()
	u.RawQuery, _ = url.QueryUnescape(u.RawQuery)
	return u.String()
}

// StringListSortUniq ensures a []string returns a sorted copy of the
// original list that does not contain any duplicate strings.
func StringListSortUniq(in []string) (out []string) {
	uniq := make(map[string]int64)
	for _, e := range in {
		uniq[e] += 1
	}
	for e := range uniq {
		out = append(out, e)
	}
	sort.Strings(out)
	return
}
