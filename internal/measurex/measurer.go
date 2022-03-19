package measurex

//
// Measurer
//
// High-level API for running measurements. The code in here
// has been designed to easily implement the new websteps
// network experiment, which is quite complex. It should be
// possible to write most other experiments using a Measurer.
//
// This file is DIFFERENT from the namesake file in probe-cli
// in that it has been edited for simplicity.
//

import (
	"context"
	"net/http"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/lucas-clemente/quic-go/http3"
)

// Measurer performs measurements. If you don't use a factory for creating
// this type, make sure you set all the MANDATORY fields.
type Measurer struct {
	// HTTP3ClientForDoH is MANDATORY and is like HTTPClientForDoH except
	// that this client only uses the HTTP3 protocol.
	HTTP3ClientForDoH model.HTTPClient

	// HTTPClientForDoH is the MANDATORY HTTPClient to use for any
	// DNS resolution using the DNS-over-HTTPS transport. This client
	// SHOULD use a transport that allows multiple connections per
	// host, so we can issue queries in parallel.
	HTTPClientForDoH model.HTTPClient

	// IDGenerator is the MANDATORY atomic variable used to generate
	// unique identifiers for measurements.
	IDGenerator *IDGenerator

	// Library is the MANDATORY network-measurement library.
	Library *Library

	// Logger is the MANDATORY logger to use.
	Logger model.Logger

	// Options contains the options. If nil, we'll use default values.
	Options *Options

	// TLSHandshaker is the MANDATORY TLS handshaker.
	TLSHandshaker model.TLSHandshaker
}

// DefaultHTTP3Transport is the default HTTP3 transport used by this library.
var DefaultHTTP3Transport = &http3.RoundTripper{}

// NewMeasurer creates a new Measurer instance using the default settings.
func NewMeasurer(logger model.Logger, library *Library) *Measurer {
	return NewMeasurerWithOptions(logger, library, &Options{})
}

// AbstractMeasurer is an abstract view of a Measurer.
type AbstractMeasurer interface {
	// DNSLookups behaves like Measurer.DNSLookups.
	DNSLookups(ctx context.Context,
		dnsLookups ...*DNSLookupPlan) <-chan *DNSLookupMeasurement

	// FlattenOptions returns flattened options.
	FlattenOptions() *Options

	// MeasureEndpoints behaves like Measurer.MeasureEndpoints.
	MeasureEndpoints(ctx context.Context,
		epnts ...*EndpointPlan) <-chan *EndpointMeasurement

	// NewURLMeasurement behaves like Measurer.NewURLMeasurement.
	NewURLMeasurement(input string) (*URLMeasurement, error)

	// NewURLRedirectDeque behaves like Measurer.NewURLRedirectDeque.
	NewURLRedirectDeque(logger model.Logger) *URLRedirectDeque

	// NextID behaves like Measurer.NextID.
	NextID() int64

	// Redirects behaves like Measurer.Redirects.
	Redirects(epnts []*EndpointMeasurement,
		opts *Options) ([]*URLMeasurement, bool)
}

var _ AbstractMeasurer = &Measurer{}

// NewMeasurerWithOptions creates a new Measurer instance with the given options.
func NewMeasurerWithOptions(
	logger model.Logger, library *Library, options *Options) *Measurer {
	return &Measurer{
		HTTP3ClientForDoH: &http.Client{Transport: DefaultHTTP3Transport},
		HTTPClientForDoH:  http.DefaultClient,
		IDGenerator:       NewIDGenerator(),
		Library:           library,
		Logger:            logger,
		Options:           options,
		TLSHandshaker:     library.NewTLSHandshakerStdlib(),
	}
}

// FlattenOptions implements AbstractMeasurer.FlattenOptions.
func (mx *Measurer) FlattenOptions() *Options {
	return mx.Options.Flatten()
}

// NextID returns the next measurement ID.
func (mx *Measurer) NextID() int64 {
	return mx.IDGenerator.NextID()
}
