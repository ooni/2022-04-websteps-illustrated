package netxlite

// This file is not part of probe-cli's netxlite. It contains a portion
// of probe-cli's internal/netxlite/tls.go that contains TLS utils.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

var (
	tlsVersionString = map[uint16]string{
		tls.VersionTLS10: "TLSv1",
		tls.VersionTLS11: "TLSv1.1",
		tls.VersionTLS12: "TLSv1.2",
		tls.VersionTLS13: "TLSv1.3",
		0:                "", // guarantee correct behaviour
	}

	tlsCipherSuiteString = map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
		tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
		tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
		0:                                           "", // guarantee correct behaviour
	}
)

// TLSVersionString returns a TLS version string. If value is zero, we
// return the empty string. If the value is unknown, we return
// `TLS_VERSION_UNKNOWN_ddd` where `ddd` is the numeric value passed
// to this function.
func TLSVersionString(value uint16) string {
	if str, found := tlsVersionString[value]; found {
		return str
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOWN_%d", value)
}

// TLSCipherSuiteString returns the TLS cipher suite as a string. If value
// is zero, we return the empty string. If we don't know the mapping from
// the value to a cipher suite name, we return `TLS_CIPHER_SUITE_UNKNOWN_ddd`
// where `ddd` is the numeric value passed to this function.
func TLSCipherSuiteString(value uint16) string {
	if str, found := tlsCipherSuiteString[value]; found {
		return str
	}
	return fmt.Sprintf("TLS_CIPHER_SUITE_UNKNOWN_%d", value)
}

// NewDefaultCertPool returns the default x509 certificate pool
// that we bundle from Mozilla. It's safe to modify the returned
// value: every invocation returns a distinct *x509.CertPool instance.
func NewDefaultCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	// Assumption: AppendCertsFromPEM cannot fail because we
	// have a test in certify_test.go that guarantees that
	pool.AppendCertsFromPEM([]byte(pemcerts))
	return pool
}
