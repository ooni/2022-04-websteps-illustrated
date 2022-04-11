package measurex

//
// Utils
//
// This is where we put free functions.
//

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
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
func PortFromURL(URL *SimpleURL) (string, error) {
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

// SortedSerializedCookiesNames returns a sorted copy of the cookies names.
func SortedSerializedCookiesNames(in []*http.Cookie) (out []string) {
	out = SerializeCookiesNames(in)
	sort.Strings(out)
	return
}

// SerializeCookiesNames takes in input []*http.Cookie and returns
// a []string where each string is a cookie name.
func SerializeCookiesNames(in []*http.Cookie) (out []string) {
	for _, cookie := range in {
		// TODO(bassosimone): in principle adding cookies like this is not
		// safe because we don't know whether their names are correct. That
		// said, we only receive cookies from the stdlib and set them also
		// using the stdlib. And the stdlib ensures cookies are okay. Should
		// we do anything else here to validate cookies names?
		out = append(out, cookie.Name)
	}
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
func CanonicalURLString(URL *SimpleURL) string {
	u := newURLWithScheme(URL, URL.Scheme)
	// TODO(bassosimone): canonicalize path if needed?
	// TODO(bassosimone): how about IDNA?
	if u.Path == "" {
		u.Path = "/"
	}
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

// GetWebPageTitle returns the title or an empty string.
func GetWebPageTitle(webpage []byte) string {
	// MK used {1,128} but we're making it larger here to get longer titles
	// e.g. <http://www.isa.gov.il/Pages/default.aspx>'s one
	re := regexp.MustCompile(`(?i)<title>([^<]{1,512})</title>`)
	v := re.FindSubmatch(webpage)
	if len(v) < 2 {
		return ""
	}
	return string(v[1])
}

// isEndpointIPv6 returns true if this endpoint uses IPv6, false otherwise.
func isEndpointIPv6(epnt string) bool {
	addr, _, err := net.SplitHostPort(epnt)
	if err != nil {
		return false
	}
	ipv6, err := netxlite.IsIPv6(addr)
	if err != nil {
		return false
	}
	return ipv6
}

// isHTTPRedirect returns true if the status code implies redirect.
func isHTTPRedirect(statusCode int64) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// ParseCookies parses one or more serialized cookies into a list of *http.Cookie.
func ParseCookies(cookie ...string) []*http.Cookie {
	// See https://stackoverflow.com/a/33926065
	header := http.Header{}
	for _, c := range cookie {
		header.Add("Set-Cookie", c)
	}
	r := &http.Response{Header: header}
	return r.Cookies()
}

// orderedMapStringToFlags is an ordered map where the keys are strings
// and the values are int64 flags. We use this map implementation in
// NewURLAddressList to guarantee a predictable order of the returned
// address list, which otherwise is random. This extra randomness isn't
// bad in general but breaks predictable cache-based reruns.
type orderdedMapStringToFlags struct {
	flags map[string]int64
	keys  []string
}

// newOrderedMapStringToFlags creates a new instance.
func newOrderedMapStringToFlags() *orderdedMapStringToFlags {
	return &orderdedMapStringToFlags{
		flags: map[string]int64{},
		keys:  []string{},
	}
}

// bitwiseOrForKey performs a bitwise or of the given flags and the
// current flags for the given key. If the key does not already exist,
// this function creates a new entry for the given key with the
// provided flags at the value associated to the key.
func (om *orderdedMapStringToFlags) bitwiseOrForKey(key string, flags int64) {
	if _, found := om.flags[key]; !found {
		om.flags[key] = 0
		om.keys = append(om.keys, key)
	}
	om.flags[key] |= flags
}

// orderedKeys returns the sequence of ordered keys.
func (om *orderdedMapStringToFlags) orderedKeys() []string {
	return om.keys
}

// get returns the element with the given key, or zero if not found.
func (om *orderdedMapStringToFlags) get(key string) int64 {
	return om.flags[key]
}
