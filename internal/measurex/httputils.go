package measurex

//
// HTTP Utils
//
// This file contains misc HTTP utilities.
//
// Note that this file is not part of ooni/probe-cli.
//

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"

	"github.com/ooni/2022-04-websteps-illustrated/internal/archival"
	"github.com/ooni/2022-04-websteps-illustrated/internal/engine/httpheader"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/ooni/2022-04-websteps-illustrated/internal/runtimex"
	"golang.org/x/net/publicsuffix"
)

// newHTTPClientWithoutRedirects creates a new HTTPClient instance that
// does not automatically perform redirects.
func (mx *Measurer) newHTTPClientWithoutRedirects(
	saver *archival.Saver, jar http.CookieJar, txp model.HTTPTransport) model.HTTPClient {
	return mx.newHTTPClient(saver, jar, txp, http.ErrUseLastResponse)
}

// ErrHTTPTooManyRedirects is the unexported error that the standard library
// would return when hitting too many redirects.
var ErrHTTPTooManyRedirects = errors.New("stopped after 10 redirects")

func (mx *Measurer) newHTTPClient(saver *archival.Saver, cookiejar http.CookieJar,
	txp model.HTTPTransport, defaultErr error) model.HTTPClient {
	return mx.Library.WrapHTTPClient(&http.Client{
		Transport: txp,
		Jar:       cookiejar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			err := defaultErr
			if len(via) >= 10 {
				err = ErrHTTPTooManyRedirects
			}
			return err
		},
	})
}

// NewCookieJar is a convenience factory for creating an http.CookieJar
// that is aware of the effective TLS / public suffix list. This
// means that the jar won't allow a domain to set cookies for another
// unrelated domain (in the public-suffix-list sense).
func NewCookieJar() http.CookieJar {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	// Safe to PanicOnError here: cookiejar.New _always_ returns nil.
	runtimex.PanicOnError(err, "cookiejar.New failed")
	return jar
}

// NewHTTPRequestHeaderForMeasuring returns an http.Header where
// the headers are the ones we use for measuring.
func NewHTTPRequestHeaderForMeasuring() http.Header {
	h := http.Header{}
	h.Set("Accept", httpheader.Accept())
	h.Set("Accept-Language", httpheader.AcceptLanguage())
	h.Set("User-Agent", httpheader.UserAgent())
	return h
}

// NewHTTPRequestWithContext is a convenience factory for creating
// a new HTTP request with the typical headers we use when performing
// measurements already set inside of req.Header.
func NewHTTPRequestWithContext(ctx context.Context,
	method, URL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, URL, body)
	if err != nil {
		return nil, err
	}
	req.Header = NewHTTPRequestHeaderForMeasuring()
	return req, nil
}

// NewHTTPGetRequest is a convenience factory for creating a new
// http.Request using the GET method and the given URL.
func NewHTTPGetRequest(ctx context.Context, URL string) (*http.Request, error) {
	return NewHTTPRequestWithContext(ctx, "GET", URL, nil)
}
