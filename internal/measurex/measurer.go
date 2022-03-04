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
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// Measurer performs measurements. If you don't use a factory for creating
// this type, make sure you set all the MANDATORY fields.
type Measurer struct {
	// DNSLookupTimeout is the MANDATORY timeout for performing
	// a DNS lookup. If not set, we use a default value.
	//
	// Note that the underlying network implementation MAY use a
	// shorter-than-you-selected watchdog timeout. In such a case,
	// the shorter watchdog timeout will prevail.
	DNSLookupTimeout time.Duration

	// HTTPGETTimeout is the MANDATORY timeout for performing
	// an HTTP GET. If not set, we use a default value.
	//
	// Note that the underlying network implementation MAY use a
	// shorter-than-you-selected watchdog timeout. In such a case,
	// the shorter watchdog timeout will prevail.
	HTTPGETTimeout time.Duration

	// IDGenerator is the MANDATORY atomic variable used to generate
	// unique identifiers for measurements.
	IDGenerator *IDGenerator

	// Library is the MANDATORY network-measurement library.
	Library *Library

	// Logger is the MANDATORY logger to use.
	Logger model.Logger

	// MaxHTTPResponseBodySnapshotSize is the maximum response body
	// snapshot size for cleartext requests (HTTP).
	MaxHTTPResponseBodySnapshotSize int64

	// MaxHTTPSResponseBodySnapshotSize is the maximum response body
	// snapshot size for encrypted requests (HTTPS/HTTP3).
	MaxHTTPSResponseBodySnapshotSize int64

	// QUICHandshakeTimeout is the MANDATORY timeout for performing
	// a QUIC handshake. If not set, we use a default value.
	//
	// Note that the underlying network implementation MAY use a
	// shorter-than-you-selected watchdog timeout. In such a case,
	// the shorter watchdog timeout will prevail.
	QUICHandshakeTimeout time.Duration

	// TCPConnectTimeout is the MANDATORY timeout for performing
	// a tcp connect. If not set, we use a default value.
	//
	// Note that the underlying network implementation MAY use a
	// shorter-than-you-selected watchdog timeout. In such a case,
	// the shorter watchdog timeout will prevail.
	TCPconnectTimeout time.Duration

	// TLSHandshakeTimeout is the MANDATORY timeout for performing
	// a tls handshake. If not set, we use a default value.
	//
	// Note that the underlying network implementation MAY use a
	// shorter-than-you-selected watchdog timeout. In such a case,
	// the shorter watchdog timeout will prevail.
	TLSHandshakeTimeout time.Duration

	// TLSHandshaker is the MANDATORY TLS handshaker.
	TLSHandshaker model.TLSHandshaker
}

const (
	// DefaultDNSLookupTimeout is the default DNS lookup timeout.
	DefaultDNSLookupTimeout = 4 * time.Second

	// DefaultHTTPGETTimeout is the default HTTP GET timeout.
	DefaultHTTPGETTimeout = 15 * time.Second

	// DefaultMaxHTTPResponseBodySnapshotSize is the default snapshot
	// size of the response body for cleartext requests.
	DefaultMaxHTTPResponseBodySnapshotSize = 1 << 19

	// DefaultMaxHTTPSResponseBodySnapshotSize is the default snapshot
	// size of the response body for cleartext requests.
	DefaultMaxHTTPSResponseBodySnapshotSize = 1 << 19

	// DefaultQUICHandshakeTimeout is the default QUIC handshake timeout.
	DefaultQUICHandshakeTimeout = 10 * time.Second

	// DefaultTCPConnectTimeout is the default TCP connect timeout.
	DefaultTCPConnectTimeout = 15 * time.Second

	// DefaultTLSHandshakeTimeout is the default TLS handshake timeout.
	DefaultTLSHandshakeTimeout = 10 * time.Second
)

// NewMeasurer creates a new Measurer instance using the default settings.
func NewMeasurer(library *Library) *Measurer {
	return &Measurer{
		DNSLookupTimeout:                 DefaultDNSLookupTimeout,
		HTTPGETTimeout:                   DefaultHTTPGETTimeout,
		IDGenerator:                      NewIDGenerator(),
		Library:                          library,
		Logger:                           model.DiscardLogger,
		MaxHTTPResponseBodySnapshotSize:  DefaultMaxHTTPResponseBodySnapshotSize,
		MaxHTTPSResponseBodySnapshotSize: DefaultMaxHTTPSResponseBodySnapshotSize,
		QUICHandshakeTimeout:             DefaultQUICHandshakeTimeout,
		TCPconnectTimeout:                DefaultTCPConnectTimeout,
		TLSHandshakeTimeout:              DefaultTLSHandshakeTimeout,
		TLSHandshaker:                    library.NewTLSHandshakerStdlib(),
	}
}

// NextID returns the next measurement ID.
func (mx *Measurer) NextID() int64 {
	return mx.IDGenerator.Next()
}
