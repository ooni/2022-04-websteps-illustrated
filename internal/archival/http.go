package archival

//
// Saves HTTP events
//

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/netxlite"
	"github.com/glaslos/tlsh"
)

// WrapHTTPTransport wraps an HTTP transport to use this saver. The
// maxBodySnapshotSize argument controls the maximum size of the body
// snapshot that we collect along with the HTTP round trip.
func (s *Saver) WrapHTTPTransport(txp model.HTTPTransport,
	maxBodySnapshotSize int64) model.HTTPTransport {
	return &httpTransportSaver{
		HTTPTransport: txp,
		mbss:          maxBodySnapshotSize,
		s:             s,
	}
}

type httpTransportSaver struct {
	model.HTTPTransport
	mbss int64
	s    *Saver
}

func (txp *httpTransportSaver) RoundTrip(req *http.Request) (*http.Response, error) {
	return txp.s.httpRoundTrip(txp.HTTPTransport, txp.mbss, req)
}

func (s *Saver) httpRoundTrip(
	txp model.HTTPTransport, maxBodySnapshotSize int64,
	req *http.Request) (*http.Response, error) {
	started := time.Now()
	resp, err := txp.RoundTrip(req)
	rt := &FlatHTTPRoundTripEvent{
		Failure:                 "",          // set later
		Finished:                time.Time{}, // set later
		Method:                  req.Method,
		RequestHeaders:          s.cloneRequestHeaders(req),
		ResponseBody:            nil, // set later
		ResponseBodyIsTruncated: false,
		ResponseBodyLength:      0,
		ResponseHeaders:         nil, // set later
		Started:                 started,
		StatusCode:              0, // set later
		Transport:               txp.Network(),
		URL:                     req.URL.String(),
	}
	s.startAggregatingNetworkEvents() // from now on, just sample
	if err != nil {
		rt.Finished = time.Now()
		rt.Failure = NewFlatFailure(err)
		s.appendHTTPRoundTripEvent(rt)
		return nil, err
	}
	rt.StatusCode = int64(resp.StatusCode)
	rt.ResponseHeaders = resp.Header.Clone()
	r := io.LimitReader(resp.Body, maxBodySnapshotSize)
	body, err := netxlite.ReadAllContext(req.Context(), r)
	if err != nil {
		rt.Finished = time.Now()
		rt.Failure = NewFlatFailure(err)
		s.appendHTTPRoundTripEvent(rt)
		return nil, err
	}
	resp.Body = &archivalHTTPTransportBody{ // allow for reading again the whole body
		Reader: io.MultiReader(bytes.NewReader(body), resp.Body),
		Closer: resp.Body,
	}
	rt.ResponseBody = body
	rt.ResponseBodyLength = int64(len(body))
	rt.ResponseBodyIsTruncated = int64(len(body)) >= maxBodySnapshotSize
	tlsh, err := tlsh.HashBytes(body)
	if err == nil {
		rt.ResponseBodyTLSH = tlsh.String()
	}
	rt.Finished = time.Now()
	s.appendHTTPRoundTripEvent(rt)
	return resp, nil
}

// cloneRequestHeaders ensure we include the Host header among the saved
// headers, which is what OONI should do, even though the Go transport is
// such that this header is added later when we're sending the request.
func (s *Saver) cloneRequestHeaders(req *http.Request) http.Header {
	header := req.Header.Clone()
	if req.Host != "" {
		header.Set("Host", req.Host)
	} else {
		header.Set("Host", req.URL.Host)
	}
	return header
}

type archivalHTTPTransportBody struct {
	io.Reader
	io.Closer
}

func (s *Saver) appendHTTPRoundTripEvent(ev *FlatHTTPRoundTripEvent) {
	s.mu.Lock()
	s.trace.HTTPRoundTrip = append(s.trace.HTTPRoundTrip, ev)
	s.mu.Unlock()
}
