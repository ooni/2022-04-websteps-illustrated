// Code generated by go generate; DO NOT EDIT.
// Generated: 2022-01-24 12:46:26.278434 +0100 CET m=+0.682175209

package netxlite

//go:generate go run ./internal/generrno/

// This enumeration lists the failures defined at
// https://github.com/ooni/spec/blob/master/data-formats/df-007-errors.md.
// Please, refer to that document for more information.
const (
	FailureAddressFamilyNotSupported    = "address_family_not_supported"
	FailureAddressInUse                 = "address_in_use"
	FailureAddressNotAvailable          = "address_not_available"
	FailureAlreadyConnected             = "already_connected"
	FailureBadAddress                   = "bad_address"
	FailureBadFileDescriptor            = "bad_file_descriptor"
	FailureConnectionAborted            = "connection_aborted"
	FailureConnectionAlreadyClosed      = "connection_already_closed"
	FailureConnectionAlreadyInProgress  = "connection_already_in_progress"
	FailureConnectionRefused            = "connection_refused"
	FailureConnectionReset              = "connection_reset"
	FailureDNSBogonError                = "dns_bogon_error"
	FailureDNSNXDOMAINError             = "dns_nxdomain_error"
	FailureDNSNoAnswer                  = "dns_no_answer"
	FailureDNSNonRecoverableFailure     = "dns_non_recoverable_failure"
	FailureDNSRefusedError              = "dns_refused_error"
	FailureDNSReplyFromUnexpectedServer = "dns_reply_from_unexpected_server"
	FailureDNSReplyWithWrongQueryID     = "dns_reply_with_wrong_query_id"
	FailureDNSServerMisbehaving         = "dns_server_misbehaving"
	FailureDNSTemporaryFailure          = "dns_temporary_failure"
	FailureDNSServfailError             = "dns_servfail_error"
	FailureDestinationAddressRequired   = "destination_address_required"
	FailureEOFError                     = "eof_error"
	FailureGenericTimeoutError          = "generic_timeout_error"
	FailureHostUnreachable              = "host_unreachable"
	FailureInterrupted                  = "interrupted"
	FailureInvalidArgument              = "invalid_argument"
	FailureJSONParseError               = "json_parse_error"
	FailureMessageSize                  = "message_size"
	FailureNetworkDown                  = "network_down"
	FailureNetworkReset                 = "network_reset"
	FailureNetworkUnreachable           = "network_unreachable"
	FailureNoBufferSpace                = "no_buffer_space"
	FailureNoProtocolOption             = "no_protocol_option"
	FailureNotASocket                   = "not_a_socket"
	FailureNotConnected                 = "not_connected"
	FailureOperationWouldBlock          = "operation_would_block"
	FailurePermissionDenied             = "permission_denied"
	FailureProtocolNotSupported         = "protocol_not_supported"
	FailureQUICIncompatibleVersion      = "quic_incompatible_version"
	FailureSSLFailedHandshake           = "ssl_failed_handshake"
	FailureSSLInvalidCertificate        = "ssl_invalid_certificate"
	FailureSSLInvalidHostname           = "ssl_invalid_hostname"
	FailureSSLUnknownAuthority          = "ssl_unknown_authority"
	FailureTimedOut                     = "timed_out"
	FailureWrongProtocolType            = "wrong_protocol_type"
)

// failureMap lists all failures so we can match them
// when they are wrapped by quic.TransportError.
var failuresMap = map[string]string{
	"address_family_not_supported":   "address_family_not_supported",
	"address_in_use":                 "address_in_use",
	"address_not_available":          "address_not_available",
	"already_connected":              "already_connected",
	"bad_address":                    "bad_address",
	"bad_file_descriptor":            "bad_file_descriptor",
	"connection_aborted":             "connection_aborted",
	"connection_already_closed":      "connection_already_closed",
	"connection_already_in_progress": "connection_already_in_progress",
	"connection_refused":             "connection_refused",
	"connection_reset":               "connection_reset",
	"destination_address_required":   "destination_address_required",
	"dns_bogon_error":                "dns_bogon_error",
	"dns_no_answer":                  "dns_no_answer",
	"dns_non_recoverable_failure":    "dns_non_recoverable_failure",
	"dns_nxdomain_error":             "dns_nxdomain_error",
	"dns_refused_error":              "dns_refused_error",
	"dns_server_misbehaving":         "dns_server_misbehaving",
	"dns_temporary_failure":          "dns_temporary_failure",
	"dns_servfail_error":             "dns_servfail_error",
	"eof_error":                      "eof_error",
	"generic_timeout_error":          "generic_timeout_error",
	"host_unreachable":               "host_unreachable",
	"interrupted":                    "interrupted",
	"invalid_argument":               "invalid_argument",
	"json_parse_error":               "json_parse_error",
	"message_size":                   "message_size",
	"network_down":                   "network_down",
	"network_reset":                  "network_reset",
	"network_unreachable":            "network_unreachable",
	"no_buffer_space":                "no_buffer_space",
	"no_protocol_option":             "no_protocol_option",
	"not_a_socket":                   "not_a_socket",
	"not_connected":                  "not_connected",
	"operation_would_block":          "operation_would_block",
	"permission_denied":              "permission_denied",
	"protocol_not_supported":         "protocol_not_supported",
	"quic_incompatible_version":      "quic_incompatible_version",
	"ssl_failed_handshake":           "ssl_failed_handshake",
	"ssl_invalid_certificate":        "ssl_invalid_certificate",
	"ssl_invalid_hostname":           "ssl_invalid_hostname",
	"ssl_unknown_authority":          "ssl_unknown_authority",
	"timed_out":                      "timed_out",
	"wrong_protocol_type":            "wrong_protocol_type",
}
