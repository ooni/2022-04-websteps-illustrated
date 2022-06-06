package baseline

//
// Contains a client for the baseline experiment.
//

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/bassosimone/websteps-illustrated/internal/archival"
	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// Client is the baseline client.
type Client struct{}

// TestKeys contains the results of the baseline experiment.
type TestKeys struct {
	DNS   *measurex.DNSLookupMeasurement
	HTTPS *measurex.EndpointMeasurement
	HTTP  *measurex.EndpointMeasurement
}

// Measure measures a given URL using the baseline methodology.
//
// Arguments:
//
// - ctx is the context for timeout/cancellation;
//
// - input is a string-serialized URL describing the website to measure;
//
// - testHelper is the test helper IP address or domain.
//
// Returns an error with nil test keys only in case of fundamental
// error (e.g., cannot parse the input URL or testHelper). In all
// the other cases, we return valid test keys with nil error.
func (c *Client) Measure(ctx context.Context, input, testHelper string) (*TestKeys, error) {
	URL, err := url.Parse(input)
	if err != nil {
		return nil, err
	}
	wg := &sync.WaitGroup{}
	dns := c.measureDNS(ctx, wg, URL.Hostname(), testHelper)
	http := c.measureHTTP(ctx, wg, URL, testHelper)
	https := c.measureHTTPS(ctx, wg, URL, testHelper)
	tk := &TestKeys{
		DNS:   <-dns,
		HTTPS: <-https,
		HTTP:  <-http,
	}
	wg.Wait()
	// TODO(bassosimone): analyze the results
	return tk, nil
}

// measureDNS performs the DNS measurement.
//
// Arguments:
//
// - ctx is the context for deadline/cancellation;
//
// - wg is the wait group to signal completion of the background goroutine;
//
// - domain is the domain to resolve;
//
// - testHelper is the test helper address or domain.
//
// Returns channel where a single DNS result will be posted.
func (c *Client) measureDNS(ctx context.Context, wg *sync.WaitGroup,
	domain, testHelper string) <-chan *measurex.DNSLookupMeasurement {
	out := make(chan *measurex.DNSLookupMeasurement)
	wg.Add(1)
	go func() {
		out <- c.doMeasureDNS(ctx, domain, testHelper)
		wg.Done()
	}()
	return out
}

// asyncMeasureDNS implements measureDNS asynchronously.
func (c *Client) doMeasureDNS(
	ctx context.Context, domain, testHelper string) *measurex.DNSLookupMeasurement {
	plans := measurex.NewDNSLookupPlans(domain, &measurex.Options{}, 0, &measurex.DNSResolverInfo{
		Network: "udp",
		Address: net.JoinHostPort(testHelper, "53"),
	})
	mx := measurex.NewMeasurerWithDefaultSettings()
	return <-mx.DNSLookups(ctx, plans...)
}

// measureHTTP performs the HTTP measurement.
//
// Arguments:
//
// - ctx is the context for deadline/cancellation;
//
// - wg is the wait group to signal completion of the background goroutine;
//
// - URL is the URL to fetch;
//
// - testHelper is the test helper address or domain.
//
// Returns channel where a single endpoint measurement will be emitted.
func (c *Client) measureHTTP(ctx context.Context, wg *sync.WaitGroup,
	URL *url.URL, testHelper string) <-chan *measurex.EndpointMeasurement {
	out := make(chan *measurex.EndpointMeasurement)
	wg.Add(1)
	go func() {
		out <- c.doMeasureHTTP(ctx, URL, testHelper)
		wg.Done()
	}()
	return out
}

// doMeasureHTTP implements measureHTTP.
func (c *Client) doMeasureHTTP(
	ctx context.Context, URL *url.URL, testHelper string) *measurex.EndpointMeasurement {
	plans := []*measurex.EndpointPlan{{
		URLMeasurementID: 0,
		Domain:           URL.Hostname(),
		Network:          archival.NetworkTypeTCP,
		Address:          net.JoinHostPort(testHelper, "80"),
		URL: &measurex.SimpleURL{
			Scheme:   "http",
			Host:     URL.Host,
			Path:     URL.Path,
			RawQuery: URL.RawQuery,
		},
		Options: &measurex.Options{
			DoNotInitiallyForceHTTPAndHTTPS: true,
			HTTPHostHeader:                  URL.Hostname(),
			HTTPRequestHeaders:              measurex.NewHTTPRequestHeaderForMeasuring(),
			MaxHTTPResponseBodySnapshotSize: 1 << 20,
		},
		Cookies: []*http.Cookie{},
	}}
	mx := measurex.NewMeasurerWithDefaultSettings()
	return <-mx.MeasureEndpoints(ctx, plans...)
}

// measureHTTPS performs the HTTPS measurement.
//
// Arguments:
//
// - ctx is the context for deadline/cancellation;
//
// - wg is the wait group to signal completion of the background goroutine;
//
// - URL is the URL to fetch;
//
// - testHelper is the test helper address or domain.
//
// Returns channel where a single endpoint measurement will be emitted.
func (c *Client) measureHTTPS(ctx context.Context, wg *sync.WaitGroup,
	URL *url.URL, testHelper string) <-chan *measurex.EndpointMeasurement {
	out := make(chan *measurex.EndpointMeasurement)
	wg.Add(1)
	go func() {
		out <- c.doMeasureHTTPS(ctx, URL, testHelper)
		wg.Done()
	}()
	return out
}

// doMeasureHTTPS implements measureHTTPS.
func (c *Client) doMeasureHTTPS(
	ctx context.Context, URL *url.URL, testHelper string) *measurex.EndpointMeasurement {
	plans := []*measurex.EndpointPlan{{
		URLMeasurementID: 0,
		Domain:           URL.Hostname(),
		Network:          archival.NetworkTypeTCP,
		Address:          net.JoinHostPort(testHelper, "443"),
		URL: &measurex.SimpleURL{
			Scheme:   "https",
			Host:     URL.Host,
			Path:     URL.Path,
			RawQuery: URL.RawQuery,
		},
		Options: &measurex.Options{
			ALPN:                            []string{"h2", "http/1.1"},
			DoNotInitiallyForceHTTPAndHTTPS: true,
			HTTPHostHeader:                  URL.Hostname(),
			HTTPRequestHeaders:              measurex.NewHTTPRequestHeaderForMeasuring(),
			MaxHTTPSResponseBodySnapshotSizeConnectivity: 1 << 20,
			MaxHTTPSResponseBodySnapshotSizeThrottling:   1 << 20,
			SNI:           URL.Hostname(),
			TLSSkipVerify: true,
		},
		Cookies: []*http.Cookie{},
	}}
	mx := measurex.NewMeasurerWithDefaultSettings()
	return <-mx.MeasureEndpoints(ctx, plans...)
}
